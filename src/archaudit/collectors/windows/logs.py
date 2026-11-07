"""Windows event logs: failed logons, RDP logons, log clearing, PowerShell logging.

Reading the Security log requires administrator rights; without them these
items are reported as not collected instead of "no failed logons".
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from archaudit import md
from archaudit.collectors.windows._ps import as_dict, as_list, denied, ps_json
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Logs"

LOGS = r"""
$thirtyDays = 2592000000
function Events([string]$Log, [string]$XPath, [int]$Max) {
    try { @(Get-WinEvent -LogName $Log -FilterXPath $XPath -MaxEvents $Max -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { @() } else { throw } }
}
function EventFields($Record) {
    $d = @{}; foreach ($n in ([xml]$Record.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' }; $d
}
$r = [ordered]@{}
try {
    $r.Failed = @(Events 'Security' "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $thirtyDays]]]" 5000 | ForEach-Object {
        $d = EventFields $_; [pscustomobject]@{ User = $d['TargetUserName']; IP = $d['IpAddress']; LogonType = $d['LogonType'] } })
} catch { $r.FailedError = $_.Exception.Message }
try {
    $r.RDP = @(Events 'Security' "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $thirtyDays]] and EventData[Data[@Name='LogonType']='10']]" 200 | ForEach-Object {
        $d = EventFields $_; [pscustomobject]@{ Time = $_.TimeCreated.ToString('s'); User = $d['TargetUserName']; IP = $d['IpAddress'] } })
} catch { $r.RDPError = $_.Exception.Message }
try {
    $r.Cleared = @(Events 'Security' "*[System[(EventID=1102) and TimeCreated[timediff(@SystemTime) <= $thirtyDays]]]" 50 | ForEach-Object { $_.TimeCreated.ToString('s') })
} catch { $r.ClearedError = $_.Exception.Message }
$r.SystemErrors = @(try { Events 'System' "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 86400000]]]" 50 | ForEach-Object {
    "$($_.TimeCreated.ToString('s')) $($_.ProviderName): $((([string]$_.Message) -split "`n")[0])" } } catch { })
$r.ScriptBlockLogging = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
$r.SecurityLogMB = try { [math]::Round((Get-WinEvent -ListLog Security -ErrorAction Stop).MaximumSizeInBytes / 1MB) } catch { $null }
[pscustomobject]$r | ConvertTo-Json -Depth 4 -Compress
"""

_LOGON_TYPES = {"2": "console", "3": "network", "7": "unlock", "8": "network (cleartext)",
                "10": "Remote Desktop", "11": "cached"}


def collect_logs(ctx: Context) -> list[Note]:
    note = Note("Logs", CAT, tags=["logs", "eventlog", "windows"])
    ctx.set_note(note.title)
    d = as_dict(ps_json(ctx, LOGS, category=CAT, what="Event logs", name="event logs",
                        timeout=max(ctx.timeout, 180)))
    if not d:
        note.summary = "not collected"
        return [note]
    failed_total = _failed(ctx, note, d)
    _rdp(ctx, note, d)
    if not _gap_if_error(ctx, d.get("ClearedError"), "Security log clearing (event 1102)"):
        cleared = [str(c) for c in as_list(d.get("Cleared"))]
        if cleared:
            ctx.finding(
                "The Security event log was cleared", Severity.HIGH, CAT,
                "Event 1102 means someone cleared the Security log in the last 30 days. "
                "Attackers do this to remove traces; it is rare during normal use.",
                "Confirm who did it and why. Consider forwarding logs to another machine.",
                evidence="\n".join(cleared), key="log-cleared",
            )
    errors = [str(e) for e in as_list(d.get("SystemErrors"))]
    if errors:
        note.add(md.callout("example", f"System errors in the last 24 hours ({len(errors)})",
                            md.code("\n".join(errors)), folded=True))
    sbl = d.get("ScriptBlockLogging") == 1
    note.add(md.heading("Logging setup"), md.kv_table([
        ("PowerShell script block logging", "on" if sbl else "off"),
        ("Security log maximum size", f"{d.get('SecurityLogMB')} MB"
         if d.get("SecurityLogMB") is not None else "unknown"),
    ]))
    if not sbl:
        ctx.finding(
            "PowerShell script block logging is off", Severity.INFO, CAT,
            "Without it, malicious PowerShell (the most common Windows attack tool) leaves "
            "little trace in the event log.",
            "gpedit: Computer Configuration → Administrative Templates → Windows Components → "
            "Windows PowerShell → Turn on PowerShell Script Block Logging.",
            key="ps-logging",
        )
    note.summary = (f"{failed_total} failed logon(s) in 30 days" if failed_total is not None
                    else "Security log not readable")
    return [note]


def _gap_if_error(ctx: Context, err: Any, item: str) -> bool:
    if not err:
        return False
    kind = GapKind.NEEDS_ROOT if denied(err) or not ctx.is_root else GapKind.ERROR
    ctx.gap(item, CAT, kind, str(err)[:200])
    return True


def _failed(ctx: Context, note: Note, d: dict[str, Any]) -> int | None:
    if _gap_if_error(ctx, d.get("FailedError"), "Failed logons (Security log, 30 days)"):
        return None
    failed = [as_dict(f) for f in as_list(d.get("Failed"))]
    sources = Counter(str(f.get("IP") or "-") for f in failed)
    users = Counter(str(f.get("User") or "?") for f in failed)
    types = Counter(_LOGON_TYPES.get(str(f.get("LogonType")), str(f.get("LogonType")))
                    for f in failed)
    note.add(md.heading("Failed logons (last 30 days)"),
             md.kv_table([("Failed logons", len(failed)), ("Distinct sources", len(sources))]),
             md.table(("Source", "Failures"), sources.most_common(15)) if failed else "",
             md.table(("Logon type", "Failures"), types.most_common()) if failed else "")
    remote = [f for f in failed if str(f.get("LogonType")) in ("3", "8", "10")]
    if len(remote) >= 20:
        ctx.finding(
            f"Password guessing: {len(remote)} failed network logons in 30 days",
            Severity.MEDIUM, CAT,
            "Repeated failed logons over the network (SMB/RDP) usually mean someone is guessing "
            "passwords. Most-targeted accounts: "
            + ", ".join(u for u, _ in users.most_common(5)) + ".",
            "Block the sources in the firewall, disable RDP/SMB exposure you don't need, and "
            "set an account lockout policy (`net accounts /lockoutthreshold:10`).",
            evidence="\n".join(f"{ip}: {n}" for ip, n in sources.most_common(10)),
            key="logon-bruteforce",
        )
    return len(failed)


def _rdp(ctx: Context, note: Note, d: dict[str, Any]) -> None:
    if _gap_if_error(ctx, d.get("RDPError"), "Remote Desktop logons (30 days)"):
        return
    rdp = [as_dict(r) for r in as_list(d.get("RDP"))]
    if rdp:
        note.add(md.heading("Remote Desktop logons (last 30 days)"),
                 md.table(("Time", "User", "From"),
                          [(r.get("Time"), r.get("User"), r.get("IP")) for r in rdp[:20]]))
