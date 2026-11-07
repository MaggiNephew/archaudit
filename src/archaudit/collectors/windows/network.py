"""Windows Firewall, listening ports, SMB, RDP, legacy name resolution, OpenSSH."""

from __future__ import annotations

from typing import Any

from archaudit import md
from archaudit.collectors.network import (
    RISKY_PORTS,
    Listener,
    parse_sshd_config,
    report_listeners,
)
from archaudit.collectors.windows._ps import as_dict, as_list, ps_json
from archaudit.core import Context, Note, Severity

CAT = "Network"

# SMB (139/445) and RPC (135) listen on every Windows machine and are covered by
# the firewall/SMB checks below; RDP is covered by its own check. WinRM over
# plain HTTP is added.
WINDOWS_RISKY_PORTS: dict[int, tuple[Severity, str]] = {
    port: v for port, v in RISKY_PORTS.items() if port not in (139, 445, 3389)
} | {5985: (Severity.MEDIUM, "WinRM over HTTP")}

NETWORK = r"""
$names = @{}
Get-Process | ForEach-Object { $names[[int]$_.Id] = [string]$_.ProcessName }
$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
                   [pscustomobject]@{ Proto = 'tcp'; Address = [string]$_.LocalAddress; Port = [int]$_.LocalPort
                                      Process = $names[[int]$_.OwningProcess] } }) +
             @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
                   [pscustomobject]@{ Proto = 'udp'; Address = [string]$_.LocalAddress; Port = [int]$_.LocalPort
                                      Process = $names[[int]$_.OwningProcess] } })
$smb = $null
try {
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    $smb = [pscustomobject]@{ SMB1 = [bool]$c.EnableSMB1Protocol; RequireSigning = [bool]$c.RequireSecuritySignature }
} catch { }
$ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
[pscustomobject]@{
    Firewall  = @(Get-NetFirewallProfile | ForEach-Object {
                    [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled
                                       Inbound = [string]$_.DefaultInboundAction } })
    Listeners = $listeners
    Profiles  = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
                    [pscustomobject]@{ Name = [string]$_.Name; Interface = [string]$_.InterfaceAlias
                                       Category = [string]$_.NetworkCategory } })
    Addresses = @(Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { [string]$_.AddressState -eq 'Preferred' } |
                  ForEach-Object { [pscustomobject]@{ Interface = [string]$_.InterfaceAlias
                                                      Address = "$($_.IPAddress)/$($_.PrefixLength)" } })
    DNS       = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } |
                  ForEach-Object { [pscustomobject]@{ Interface = [string]$_.InterfaceAlias
                                                      Servers = ($_.ServerAddresses -join ', ') } })
    SMB       = $smb
    SMB1Reg   = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
    RDPDeny   = Reg $ts 'fDenyTSConnections'
    RDPNLA    = Reg "$ts\WinStations\RDP-Tcp" 'UserAuthentication'
    LLMNR     = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    NetBIOS   = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object {
                    [pscustomobject]@{ Adapter = [string]$_.Description; Option = [int]$_.TcpipNetbiosOptions } })
    SSHD      = [string](Get-CimInstance Win32_Service -Filter "Name='sshd'").State
} | ConvertTo-Json -Depth 4 -Compress
"""


def collect_network(ctx: Context) -> list[Note]:
    note = Note("Network", CAT, tags=["network", "firewall", "windows"])
    ctx.set_note(note.title)
    d = as_dict(ps_json(ctx, NETWORK, category=CAT, what="Network configuration",
                        name="network"))
    if not d:
        note.summary = "not collected"
        return [note]

    note.add(md.heading("Addresses"),
             md.table(("Interface", "Address"), [(a.get("Interface"), a.get("Address"))
                                                 for a in map(as_dict, as_list(d.get("Addresses")))]),
             md.table(("Network", "Interface", "Profile"),
                      [(p.get("Name"), p.get("Interface"), p.get("Category"))
                       for p in map(as_dict, as_list(d.get("Profiles")))]),
             md.table(("Interface", "DNS servers"), [(x.get("Interface"), x.get("Servers"))
                                                     for x in map(as_dict, as_list(d.get("DNS")))]))
    firewall_on = _firewall(ctx, note, [as_dict(f) for f in as_list(d.get("Firewall"))])
    listeners = sorted({Listener(str(x.get("Proto")), str(x.get("Address")), int(x.get("Port") or 0),
                                 str(x.get("Process") or ""))
                        for x in map(as_dict, as_list(d.get("Listeners")))},
                       key=lambda x: (x.port, x.proto, x.address))
    exposed = report_listeners(ctx, note, listeners, firewall_on, partial_processes=False,
                               risky_ports=WINDOWS_RISKY_PORTS)
    _smb(ctx, note, d)
    _rdp(ctx, note, d)
    _name_resolution(ctx, d)
    note.summary = (f"{exposed} network-reachable port(s), firewall: "
                    f"{'on' if firewall_on else 'OFF on some profiles'}")
    return [note, _ssh(ctx, str(d.get("SSHD") or ""))]


def _firewall(ctx: Context, note: Note, profiles: list[dict[str, Any]]) -> bool:
    note.add(md.heading("Windows Firewall"),
             md.table(("Profile", "Enabled", "Default inbound"),
                      [(p.get("Name"), p.get("Enabled"), p.get("Inbound")) for p in profiles]))
    off = [str(p.get("Name")) for p in profiles if str(p.get("Enabled")) in ("False", "0")]
    allow = [str(p.get("Name")) for p in profiles if str(p.get("Inbound")) == "Allow"]
    if off:
        ctx.finding(
            "Windows Firewall is off for some network profiles",
            Severity.HIGH if "Public" in off else Severity.MEDIUM, CAT,
            "With the firewall off, every listening service on this PC is reachable from the "
            "network it is connected to" + (", including public Wi-Fi." if "Public" in off
                                             else "."),
            "Windows Security → Firewall & network protection → turn the firewall on for each "
            "profile.",
            evidence="disabled: " + ", ".join(off), key="firewall-off",
        )
    if allow:
        ctx.finding(
            "Firewall allows inbound connections by default", Severity.HIGH, CAT,
            "The default inbound action is Allow, so the firewall only blocks what a rule "
            "explicitly blocks.",
            "`Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block` "
            "from an administrator PowerShell.",
            evidence="default inbound Allow: " + ", ".join(allow), key="firewall-allow",
        )
    return bool(profiles) and not off


def _smb(ctx: Context, note: Note, d: dict[str, Any]) -> None:
    smb = as_dict(d.get("SMB"))
    smb1 = smb.get("SMB1") is True or d.get("SMB1Reg") == 1
    note.add(md.heading("File sharing (SMB)"), md.kv_table([
        ("SMBv1 server", "enabled" if smb1 else "disabled" if smb else
         "unknown (run as administrator)" if not ctx.is_root else "disabled"),
        ("Signing required", "yes" if smb.get("RequireSigning") is True else
         "no" if smb.get("RequireSigning") is False else "unknown"),
    ]))
    if smb1:
        ctx.finding(
            "SMBv1 is enabled", Severity.HIGH, CAT,
            "SMBv1 is the protocol abused by WannaCry and NotPetya; it has no modern security "
            "features and is not needed by current devices.",
            "`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` from an "
            "administrator PowerShell, then restart.",
            references=["https://learn.microsoft.com/windows-server/storage/file-server/"
                        "troubleshoot/detect-enable-and-disable-smbv1-v2-v3"],
            key="smb1",
        )


def _rdp(ctx: Context, note: Note, d: dict[str, Any]) -> None:
    enabled = d.get("RDPDeny") == 0
    nla = d.get("RDPNLA") != 0
    note.add(md.heading("Remote Desktop"),
             md.kv_table([("Remote Desktop", "enabled" if enabled else "disabled"),
                          ("Network Level Authentication", "required" if nla else "NOT required")]))
    if enabled and not nla:
        ctx.finding(
            "Remote Desktop accepts connections without Network Level Authentication",
            Severity.HIGH, CAT,
            "Without NLA, anyone who can reach port 3389 gets a login screen before "
            "authenticating, which exposes the server to pre-authentication exploits "
            "(e.g. BlueKeep) and password guessing.",
            "System Properties → Remote → allow connections only from computers running Remote "
            "Desktop with Network Level Authentication.", key="rdp-nla",
        )
    elif enabled:
        ctx.finding(
            "Remote Desktop is enabled", Severity.INFO, CAT,
            "Remote Desktop is a frequent target for password guessing when reachable from "
            "the internet.",
            "Turn it off if unused (Settings → System → Remote Desktop); otherwise keep it "
            "behind a VPN and use strong passwords.", key="rdp",
        )


def _name_resolution(ctx: Context, d: dict[str, Any]) -> None:
    issues = []
    if d.get("LLMNR") != 0:
        issues.append("LLMNR is enabled (no policy setting EnableMulticast=0)")
    netbios = [str(a.get("Adapter")) for a in map(as_dict, as_list(d.get("NetBIOS")))
               if a.get("Option") != 2]  # 2 = disabled
    if netbios:
        issues.append("NetBIOS over TCP/IP is not disabled on: " + ", ".join(netbios))
    if issues:
        ctx.finding(
            "Legacy name resolution (LLMNR / NetBIOS) is enabled", Severity.LOW, CAT,
            "When DNS fails, Windows asks the local network who a name belongs to. Anyone on "
            "the same network (e.g. public Wi-Fi) can answer and capture password hashes "
            "(Responder-style attacks).",
            "Disable LLMNR (gpedit: Computer Configuration → Administrative Templates → Network "
            "→ DNS Client → Turn off multicast name resolution) and set NetBIOS to Disabled in "
            "each adapter's IPv4 → Advanced → WINS settings.",
            evidence="\n".join(issues), key="llmnr-netbios",
        )


def _ssh(ctx: Context, state: str) -> Note:
    note = Note("SSH Server", CAT, tags=["network", "ssh", "windows"])
    ctx.set_note(note.title)
    if not state:
        note.summary = "OpenSSH server not installed"
        note.add(md.callout("success", "Not installed", "No SSH server attack surface."))
        return note
    opts = parse_sshd_config(ctx, "/ProgramData/ssh/sshd_config", base="/ProgramData/ssh")
    pw_login = opts.get("passwordauthentication", "yes").lower()
    note.summary = f"sshd {state.lower()}, password login: {pw_login}"
    note.add(md.kv_table([("Service state", state), ("PasswordAuthentication", pw_login),
                          ("PermitEmptyPasswords", opts.get("permitemptypasswords", "no"))]))
    if state != "Running":
        return note
    if opts.get("permitemptypasswords", "no").lower() == "yes":
        ctx.finding("SSH allows empty passwords", Severity.CRITICAL, CAT,
                    "Accounts without a password can log in over the network.",
                    "Set `PermitEmptyPasswords no` in `C:\\ProgramData\\ssh\\sshd_config` and "
                    "restart the sshd service.")
    if pw_login == "yes":
        ctx.finding("SSH accepts password logins", Severity.MEDIUM, CAT,
                    "The OpenSSH server accepts passwords (the default), so it can be "
                    "brute-forced.",
                    "Set up key-based login, then set `PasswordAuthentication no` in "
                    "`C:\\ProgramData\\ssh\\sshd_config` and `Restart-Service sshd`.")
    return note
