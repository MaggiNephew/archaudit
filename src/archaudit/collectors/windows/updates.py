"""Windows Update state and installed software (read-only).

The Windows Update Agent COM API is only *searched*: nothing is downloaded or
installed. With ``--offline`` the search uses the locally cached catalogue.
"""

from __future__ import annotations

from datetime import datetime

from archaudit import md
from archaudit.collectors.windows._ps import as_dict, as_list, denied, ps_json
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Packages"

_UPDATES = r"""
$r = [ordered]@{}
$searcher = $null
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = __ONLINE__
    $found = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $r.Pending = @($found.Updates | ForEach-Object {
        [pscustomobject]@{ Title = [string]$_.Title; Severity = [string]$_.MsrcSeverity
                           KB = ($_.KBArticleIDs -join ',')
                           Categories = (@($_.Categories | ForEach-Object { [string]$_.Name }) -join ', ') } })
} catch { $r.PendingError = $_.Exception.Message }
try {
    $count = $searcher.GetTotalHistoryCount()
    $history = @($searcher.QueryHistory(0, [math]::Min($count, 300)) |
                 Where-Object { $_.ResultCode -eq 2 -and $_.Operation -eq 1 -and $_.Title -notmatch 'Defender|Security Intelligence|KB2267602' } |
                 Sort-Object Date -Descending)
    if ($history) { $r.LastInstall = $history[0].Date.ToString('s'); $r.LastInstallTitle = [string]$history[0].Title }
} catch { $r.HistoryError = $_.Exception.Message }
$r.RebootPending = (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
                   (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$r.NoAutoUpdate = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
$r.ServiceStart = [string](Get-CimInstance Win32_Service -Filter "Name='wuauserv'").StartMode
$r.Hotfixes = @(Get-HotFix | ForEach-Object {
    [pscustomobject]@{ Id = [string]$_.HotFixID; Description = [string]$_.Description
                       InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { $null } } })
[pscustomobject]$r | ConvertTo-Json -Depth 4 -Compress
"""

SOFTWARE = r"""
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
@(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
  ForEach-Object { [pscustomobject]@{ Name = [string]$_.DisplayName; Version = [string]$_.DisplayVersion
                                      Publisher = [string]$_.Publisher } } |
  Sort-Object Name -Unique) | ConvertTo-Json -Compress
"""


def updates_script(online: bool) -> str:
    return _UPDATES.replace("__ONLINE__", "$true" if online else "$false")


def is_security_update(update: dict[str, object]) -> bool:
    cats = str(update.get("Categories", ""))
    return bool(update.get("Severity")) or "Security Updates" in cats


def collect_updates(ctx: Context) -> list[Note]:
    note = Note("Updates & Software", CAT, tags=["updates", "software", "windows"])
    ctx.set_note(note.title)
    d = as_dict(ps_json(ctx, updates_script(not ctx.offline), category=CAT,
                        what="Windows Update status", name="Windows Update",
                        timeout=max(ctx.timeout, 600)))
    if d:
        _updates(ctx, note, d)
    software = [as_dict(s) for s in as_list(ps_json(ctx, SOFTWARE, category=CAT,
                                                       what="Installed programs",
                                                       name="installed programs"))]
    if software:
        note.add(md.heading("Installed programs"),
                 md.callout("example", f"{len(software)} programs",
                            md.table(("Name", "Version", "Publisher"),
                                     [(s.get("Name"), s.get("Version"), s.get("Publisher"))
                                      for s in software]), folded=True),
                 md.callout("tip", "Third-party updates",
                            "Windows Update does not update most third-party programs. "
                            "`winget upgrade --all` updates the ones winget knows about."))
    note.summary = (f"{ctx.facts.get('pending_updates', 'unknown')} update(s) pending, "
                    f"{len(software)} programs installed")
    return [note]


def _updates(ctx: Context, note: Note, d: dict[str, object]) -> None:
    pending = [as_dict(u) for u in as_list(d.get("Pending"))]
    if err := d.get("PendingError"):
        kind = GapKind.NEEDS_ROOT if denied(err) else GapKind.ERROR
        ctx.gap("Pending Windows updates", CAT, kind, str(err)[:200],
                "Check that the Windows Update service is not disabled"
                if kind is GapKind.ERROR else "")
    else:
        security = [u for u in pending if is_security_update(u)]
        definitions = [u for u in pending if "Definition Updates" in str(u.get("Categories"))]
        other = [u for u in pending if u not in security and u not in definitions]
        ctx.facts["pending_updates"] = str(len(pending))
        ctx.facts["vulnerable_packages"] = f"{len(security)} security update(s) pending"
        note.add(md.heading("Pending updates"),
                 md.callout("info", "Offline search",
                            "`--offline`: searched the locally cached catalogue only.")
                 if ctx.offline else "",
                 md.table(("Update", "Severity", "KB", "Category"),
                          [(u.get("Title"), u.get("Severity") or "—", u.get("KB"),
                            u.get("Categories")) for u in pending])
                 if pending else md.callout("success", "Up to date",
                                            "Windows Update reports no pending updates."))
        if security:
            ctx.finding(
                f"{len(security)} Windows security update(s) pending", Severity.HIGH, CAT,
                "Security updates are available but not installed; they fix vulnerabilities "
                "that are publicly documented once released.",
                "Settings → Windows Update → Check for updates → install, then restart.",
                evidence="\n".join(f"{u.get('Severity') or 'security'}: {u.get('Title')}"
                                   for u in security), key="security-updates",
            )
        if other:
            ctx.finding(
                f"{len(other)} other Windows update(s) pending", Severity.LOW, CAT,
                "Non-security updates (drivers, feature or quality updates) are available.",
                "Settings → Windows Update.",
                evidence="\n".join(str(u.get("Title")) for u in other), key="pending-updates",
            )

    hotfixes = [as_dict(h) for h in as_list(d.get("Hotfixes"))]
    last = str(d.get("LastInstall") or "")
    if not last:  # fall back to the newest hotfix date
        dates = sorted(str(h["InstalledOn"]) for h in hotfixes if h.get("InstalledOn"))
        last = dates[-1] if dates else ""
    age = None
    if last:
        try:
            age = (datetime.now() - datetime.fromisoformat(last)).days
        except ValueError:
            age = None
    ctx.facts["last_upgrade"] = f"{last[:10]} ({age} days ago)" if age is not None else "unknown"
    note.add(md.heading("Update history"), md.kv_table([
        ("Last successful update", ctx.facts["last_upgrade"]),
        ("Last update installed", d.get("LastInstallTitle")),
        ("Restart pending", "yes" if d.get("RebootPending") else "no"),
        ("Windows Update service", d.get("ServiceStart")),
        ("Automatic updates disabled by policy", "yes" if d.get("NoAutoUpdate") == 1 else "no"),
    ]), md.callout("example", f"{len(hotfixes)} installed hotfixes",
                   md.table(("KB", "Type", "Installed"),
                            [(h.get("Id"), h.get("Description"), h.get("InstalledOn"))
                             for h in hotfixes]), folded=True))
    if age is not None and age > 45:
        ctx.finding(
            f"No Windows updates installed for {age} days", Severity.MEDIUM, CAT,
            "Windows publishes security fixes monthly (Patch Tuesday). Nothing has been "
            "installed for more than six weeks, so recent fixes are probably missing.",
            "Settings → Windows Update → Check for updates. If updates keep failing, run the "
            "Windows Update troubleshooter.",
            evidence=f"last successful update: {last}", key="stale-upgrade",
        )
    if d.get("RebootPending"):
        ctx.finding(
            "Restart required to finish installing updates", Severity.MEDIUM, CAT,
            "Updates are installed but not active until Windows restarts.",
            "Restart the computer.", key="reboot-pending",
        )
    if d.get("NoAutoUpdate") == 1 or str(d.get("ServiceStart")) == "Disabled":
        ctx.finding(
            "Automatic Windows updates are disabled", Severity.MEDIUM, CAT,
            "Windows Update is disabled by policy or its service is disabled, so security "
            "fixes are not installed automatically.",
            "Remove the `NoAutoUpdate` policy (gpedit: Computer Configuration → Administrative "
            "Templates → Windows Components → Windows Update) and set the Windows Update "
            "service to Manual.",
            evidence=f"NoAutoUpdate={d.get('NoAutoUpdate')} wuauserv={d.get('ServiceStart')}",
            key="auto-updates",
        )
