"""Windows services, scheduled tasks and autostart entries.

Looks for the classic local privilege-escalation paths: service or task
binaries (and their folders) that non-admin users can modify, and unquoted
service paths with spaces.
"""

from __future__ import annotations

from typing import Any

from archaudit import md
from archaudit.collectors.windows._ps import WEAK_ACL, as_dict, as_list, ps_json
from archaudit.core import Context, Note, Severity

CAT = "Services"

LEGACY_SERVICES = {
    "TlntSvr": (Severity.HIGH, "Telnet server (cleartext remote login)"),
    "RemoteRegistry": (Severity.MEDIUM, "Remote Registry"),
    "SNMP": (Severity.LOW, "SNMP service"),
    "FTPSVC": (Severity.MEDIUM, "IIS FTP server"),
    "simptcp": (Severity.LOW, "Simple TCP/IP services"),
}

SERVICES = WEAK_ACL + r"""
function ExePath([string]$Command) {
    if (-not $Command) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($c.StartsWith('"')) { $end = $c.IndexOf('"', 1); if ($end -gt 0) { return $c.Substring(1, $end - 1) } }
    $i = $c.ToLower().IndexOf('.exe')
    if ($i -ge 0) { return $c.Substring(0, $i + 4) }
    return ($c -split ' ')[0]
}
$windir = $env:SystemRoot.ToLower()
$services = @(Get-CimInstance Win32_Service | ForEach-Object {
    $exe = ExePath $_.PathName
    $outside = $exe -and -not $exe.ToLower().StartsWith($windir)
    [pscustomobject]@{
        Name = [string]$_.Name; Display = [string]$_.DisplayName; State = [string]$_.State
        Start = [string]$_.StartMode; Account = [string]$_.StartName; Path = [string]$_.PathName; Exe = $exe
        WeakExe = if ($outside -and (Test-Path -LiteralPath $exe -PathType Leaf)) { WeakAcl $exe } else { $null }
        WeakDir = if ($outside) { $dir = Split-Path -Parent $exe; if ($dir -and (Test-Path -LiteralPath $dir)) { WeakAcl $dir $true } } else { $null }
    } })
$tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $first = @($_.Actions | Where-Object { $_.Execute })[0]
    $exe = if ($first) { [Environment]::ExpandEnvironmentVariables($first.Execute.Trim('"')) } else { $null }
    [pscustomobject]@{
        Name = [string]$_.TaskName; Path = [string]$_.TaskPath; State = [string]$_.State
        User = [string]$_.Principal.UserId; RunLevel = [string]$_.Principal.RunLevel
        Action = (@($_.Actions | Where-Object { $_.Execute } | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | ')
        WeakExe = if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) { WeakAcl $exe } else { $null }
    } })
$run = @()
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
               'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') {
    try {
        $p = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
        foreach ($v in $p.PSObject.Properties) {
            if ($v.Name -notlike 'PS*') { $run += [pscustomobject]@{ Key = $k; Name = [string]$v.Name; Command = [string]$v.Value } }
        }
    } catch { }
}
$startup = @(foreach ($d in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
    if ($d -and (Test-Path -LiteralPath $d)) { Get-ChildItem -LiteralPath $d -File | ForEach-Object { [string]$_.FullName } } })
[pscustomobject]@{ Services = $services; Tasks = $tasks; Run = $run; Startup = $startup } |
    ConvertTo-Json -Depth 4 -Compress
"""

PRIVILEGED_ACCOUNTS = ("localsystem", "nt authority\\system", "nt authority\\localservice",
                       "nt authority\\networkservice")


def unquoted_path(path: str, exe: str, windir: str = "c:\\windows") -> bool:
    """``C:\\Program Files\\Some App\\svc.exe`` without quotes: Windows tries
    ``C:\\Program.exe`` and ``C:\\Program Files\\Some.exe`` first."""
    p = path.strip()
    return bool(p) and not p.startswith('"') and " " in (exe or "") \
        and not (exe or "").lower().startswith(windir)


def collect_services(ctx: Context) -> list[Note]:
    note = Note("Services", CAT, tags=["services", "autostart", "windows"])
    ctx.set_note(note.title)
    d = as_dict(ps_json(ctx, SERVICES, category=CAT, what="Services and scheduled tasks",
                        name="services and tasks", timeout=max(ctx.timeout, 180)))
    if not d:
        note.summary = "not collected"
        return [note]
    services = [as_dict(s) for s in as_list(d.get("Services"))]
    tasks = [as_dict(t) for t in as_list(d.get("Tasks"))]
    running = [s for s in services if s.get("State") == "Running"]
    note.summary = f"{len(running)} running services, {len(tasks)} non-Microsoft scheduled tasks"

    note.add(md.heading("Running services"),
             md.callout("example", f"{len(running)} running",
                        md.table(("Service", "Name", "Start", "Account", "Binary"),
                                 [(s.get("Display"), s.get("Name"), s.get("Start"),
                                   s.get("Account"), s.get("Exe")) for s in running]),
                        folded=True))
    note.add(md.heading("Scheduled tasks (non-Microsoft)"),
             md.table(("Task", "State", "Runs as", "Level", "Action"),
                      [(f"{t.get('Path')}{t.get('Name')}", t.get("State"), t.get("User"),
                        t.get("RunLevel"), t.get("Action")) for t in tasks]))
    run = [as_dict(r) for r in as_list(d.get("Run"))]
    startup = [str(s) for s in as_list(d.get("Startup"))]
    note.add(md.heading("Autostart"),
             md.table(("Registry key", "Name", "Command"),
                      [(r.get("Key"), r.get("Name"), r.get("Command")) for r in run]),
             md.bullet(startup) if startup else "")
    _weak_binaries(ctx, services, tasks)
    _unquoted(ctx, services)
    for s in running:
        if (name := str(s.get("Name"))) in LEGACY_SERVICES:
            sev, what = LEGACY_SERVICES[name]
            ctx.finding(f"Legacy/risky service running: {what}", sev, CAT,
                        f"`{name}` exposes a legacy or remote-administration interface that "
                        "is rarely needed on a workstation.",
                        f"`Stop-Service {name}; Set-Service {name} -StartupType Disabled` "
                        "(admin PowerShell) if you don't need it.", key=f"legacy-{name}")
    return [note]


def _weak_binaries(ctx: Context, services: list[dict[str, Any]],
                   tasks: list[dict[str, Any]]) -> None:
    weak_svc = [f"{s.get('Name')} ({s.get('Account')}): {s.get('Exe')} — {s.get('WeakExe')}"
                for s in services if s.get("WeakExe")]
    weak_dir = [f"{s.get('Name')} ({s.get('Account')}): folder of {s.get('Exe')} — "
                f"{s.get('WeakDir')}" for s in services if s.get("WeakDir") and not s.get("WeakExe")]
    if weak_svc or weak_dir:
        ctx.finding(
            "Service binaries or folders writable by non-admin users", Severity.HIGH, CAT,
            "A standard user can replace these service executables (or drop a DLL next to "
            "them); the code then runs with the service's account, usually SYSTEM, at the next "
            "service start: local privilege escalation.",
            "Remove write access for Users/Authenticated Users/Everyone: "
            "`icacls \"<path>\" /remove:g *S-1-5-32-545 *S-1-5-11 *S-1-1-0` (admin), or "
            "reinstall the program into Program Files.",
            evidence="\n".join(weak_svc + weak_dir), key="weak-service-binary",
        )
    weak_task = [f"{t.get('Path')}{t.get('Name')} (runs as {t.get('User') or '?'}, "
                 f"{t.get('RunLevel')}): {t.get('Action')} — {t.get('WeakExe')}"
                 for t in tasks if t.get("WeakExe")]
    if weak_task:
        ctx.finding(
            "Scheduled task programs writable by non-admin users", Severity.HIGH, CAT,
            "Anyone who can modify these programs gets their code run by the task, with the "
            "task's account and privileges.",
            "Remove write access for non-admin groups with `icacls`, or move the program into "
            "a protected folder.",
            evidence="\n".join(weak_task), key="weak-task-binary",
        )


def _unquoted(ctx: Context, services: list[dict[str, Any]]) -> None:
    hits = [f"{s.get('Name')} ({s.get('Account')}): {s.get('Path')}" for s in services
            if unquoted_path(str(s.get("Path") or ""), str(s.get("Exe") or ""))
            and str(s.get("Account") or "").lower() in PRIVILEGED_ACCOUNTS]
    if hits:
        ctx.finding(
            "Unquoted service paths with spaces", Severity.MEDIUM, CAT,
            "Windows resolves an unquoted path like `C:\\Program Files\\My App\\svc.exe` by "
            "trying `C:\\Program.exe` and `C:\\Program Files\\My.exe` first. If any of those "
            "folders is writable by a standard user, a planted program runs as the service "
            "account.",
            "Quote the path: `sc.exe config <name> binPath= \"\\\"C:\\path with spaces\\svc.exe\\\"\"` "
            "(admin), or ask the vendor for a fixed installer.",
            evidence="\n".join(hits), key="unquoted-service-path",
        )
