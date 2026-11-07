"""Windows boot chain and platform security, plus antivirus / Defender state."""

from __future__ import annotations

from typing import Any

from archaudit import md
from archaudit.collectors.windows._ps import as_dict, as_list, denied, ps_json
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Kernel & Boot"
AV_CAT = "Antivirus"
MS_DOCS = "https://learn.microsoft.com/windows/security/"

PLATFORM = r"""
$dg = $null
try { $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop } catch { }
$tpm = $null; $tpmError = $null
try {
    $t = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop
    if ($t) { $tpm = [pscustomobject]@{ Present = $true; Enabled = [bool]$t.IsEnabled_InitialValue;
                                        Activated = [bool]$t.IsActivated_InitialValue; Spec = [string]$t.SpecVersion } }
    else { $tpm = [pscustomobject]@{ Present = $false } }
} catch { $tpmError = $_.Exception.Message }
$sb = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
[pscustomobject]@{
    UEFI               = Test-Path -LiteralPath $sb
    SecureBoot         = Reg $sb 'UEFISecureBootEnabled'
    VBSStatus          = if ($dg) { [int]$dg.VirtualizationBasedSecurityStatus } else { $null }
    ServicesRunning    = if ($dg) { @($dg.SecurityServicesRunning | ForEach-Object { [int]$_ }) } else { @() }
    ServicesConfigured = if ($dg) { @($dg.SecurityServicesConfigured | ForEach-Object { [int]$_ }) } else { @() }
    RunAsPPL           = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    WDigest            = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    DEP                = [int](Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy
    SmartScreen        = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
    Tpm                = $tpm
    TpmError           = $tpmError
} | ConvertTo-Json -Depth 3 -Compress
"""

DEFENDER = r"""
$status = $null; $statusError = $null
try {
    $s = Get-MpComputerStatus -ErrorAction Stop
    $status = [pscustomobject]@{
        ServiceEnabled = [bool]$s.AMServiceEnabled; AntivirusEnabled = [bool]$s.AntivirusEnabled
        RealTime = [bool]$s.RealTimeProtectionEnabled; Behavior = [bool]$s.BehaviorMonitorEnabled
        TamperProtected = [bool]$s.IsTamperProtected; SignatureAgeDays = [int]$s.AntivirusSignatureAge
        QuickScanAgeDays = [int]$s.QuickScanAge; Mode = [string]$s.AMRunningMode
    }
} catch { $statusError = $_.Exception.Message }
$prefs = $null
try {
    $p = Get-MpPreference -ErrorAction Stop
    $prefs = [pscustomobject]@{
        ExclusionPath = @($p.ExclusionPath | Where-Object { $_ }); ExclusionProcess = @($p.ExclusionProcess | Where-Object { $_ })
        ExclusionExtension = @($p.ExclusionExtension | Where-Object { $_ }); PUAProtection = [int]$p.PUAProtection
        NetworkProtection = [int]$p.EnableNetworkProtection; CloudProtection = [int]$p.MAPSReporting
    }
} catch { }
$products = @()
try {
    $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
                  ForEach-Object { [pscustomobject]@{ Name = [string]$_.displayName; State = [int]$_.productState } })
} catch { }
[pscustomobject]@{ Status = $status; StatusError = $statusError; Preferences = $prefs; Products = $products } |
    ConvertTo-Json -Depth 4 -Compress
"""

_VBS = {0: "off", 1: "enabled but not running", 2: "running"}
_DEP = {0: "AlwaysOff", 1: "AlwaysOn", 2: "OptIn (default)", 3: "OptOut"}


def collect_platform_security(ctx: Context) -> list[Note]:
    note = Note("Boot & Platform Security", CAT, tags=["boot", "security", "windows"])
    ctx.set_note(note.title)
    d = as_dict(ps_json(ctx, PLATFORM, category=CAT, what="Boot and platform security",
                        name="platform security"))
    if not d:
        note.summary = "not collected"
        return [note]
    running = set(as_list(d.get("ServicesRunning")))
    configured = set(as_list(d.get("ServicesConfigured")))
    uefi, sb = bool(d.get("UEFI")), d.get("SecureBoot")
    secure_boot = ("n/a (legacy BIOS)" if not uefi else
                   "enabled" if sb == 1 else "disabled" if sb == 0 else "unknown")
    tpm = as_dict(d.get("Tpm"))
    if d.get("TpmError"):
        tpm_text = "unknown"
        kind = GapKind.NEEDS_ROOT if denied(d["TpmError"]) or not ctx.is_root else GapKind.ERROR
        ctx.gap("TPM status", CAT, kind, str(d["TpmError"])[:200])
    elif not tpm.get("Present"):
        tpm_text = "not present"
    else:
        tpm_text = (f"present, {'enabled' if tpm.get('Enabled') else 'disabled'}, "
                    f"spec {str(tpm.get('Spec', '')).split(',')[0]}")
    hvci, cred_guard = 2 in running, 1 in running
    ppl = d.get("RunAsPPL") in (1, 2)
    note.summary = f"Secure Boot {secure_boot}, memory integrity {'on' if hvci else 'off'}"
    note.add(md.heading("Boot"), md.kv_table([
        ("Firmware", "UEFI" if uefi else "BIOS / legacy"), ("Secure Boot", secure_boot),
        ("TPM", tpm_text)]))
    note.add(md.heading("Platform protections"), md.kv_table([
        ("Virtualization-based security", _VBS.get(d.get("VBSStatus"), "unknown")),  # type: ignore[arg-type]
        ("Memory integrity (HVCI)", "running" if hvci else
         "configured, not running" if 2 in configured else "off"),
        ("Credential Guard", "running" if cred_guard else "off"),
        ("LSA protection (RunAsPPL)", "on" if ppl else "off"),
        ("DEP policy", _DEP.get(d.get("DEP"), str(d.get("DEP")))),  # type: ignore[arg-type]
        ("SmartScreen (Explorer)", d.get("SmartScreen") or "default"),
    ]))
    if uefi and sb == 0:
        ctx.finding(
            "Secure Boot is disabled", Severity.MEDIUM, CAT,
            "Without Secure Boot, bootkits and tampered boot loaders can run before Windows "
            "and its protections start. Windows supports Secure Boot out of the box.",
            "Enable Secure Boot in the UEFI firmware setup (often under Boot or Security). "
            "Check first that BitLocker recovery keys are saved.",
            references=[MS_DOCS + "operating-system-security/system-security/secure-the-windows-10-boot-process"],
        )
    if not uefi:
        ctx.finding(
            "Windows boots in legacy BIOS mode", Severity.LOW, CAT,
            "Legacy BIOS boot rules out Secure Boot and several hardware-backed protections.",
            "Convert the disk to GPT (`mbr2gpt /convert`) and switch the firmware to UEFI.",
        )
    if not hvci:
        ctx.finding(
            "Memory integrity (HVCI) is off", Severity.MEDIUM, CAT,
            "Memory integrity blocks unsigned or known-vulnerable kernel drivers, a common "
            "way for malware to disable security tools (\"bring your own vulnerable driver\").",
            "Windows Security → Device security → Core isolation → Memory integrity: On. "
            "If it refuses, update or remove the incompatible drivers it lists.",
            key="hvci",
        )
    if not ppl:
        ctx.finding(
            "LSA protection is off", Severity.LOW, CAT,
            "LSA protection runs the process that holds logon secrets (lsass) as a protected "
            "process, so tools like Mimikatz cannot read credentials from it.",
            "Windows Security → Device security → Core isolation → Local Security Authority "
            "protection: On, then reboot.",
            key="lsa-ppl",
        )
    if d.get("WDigest") == 1:
        ctx.finding(
            "WDigest stores logon passwords in memory", Severity.HIGH, CAT,
            "`UseLogonCredential = 1` makes Windows keep plaintext passwords in LSASS memory, "
            "where credential-dumping tools read them. Attackers set this for persistence.",
            "Delete `UseLogonCredential` under `HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
            "SecurityProviders\\WDigest` (or set it to 0) and investigate who set it.",
        )
    if d.get("DEP") == 0:
        ctx.finding("Data Execution Prevention is disabled", Severity.HIGH, CAT,
                    "DEP is set to AlwaysOff, removing a basic exploit mitigation.",
                    "`bcdedit /set {current} nx OptIn` from an administrator prompt, then reboot.")
    if tpm.get("Present") is False:
        ctx.finding("No TPM detected", Severity.INFO, CAT,
                    "Without a TPM, BitLocker needs a password/USB key and Windows Hello and "
                    "measured boot are weaker.",
                    "Enable the TPM (often called PTT or fTPM) in the firmware setup.")
    return [note]


def _product_on(state: int) -> bool:
    """SecurityCenter2 productState: 0x1000 bit = real-time protection on."""
    return bool(state & 0x1000)


def _product_outdated(state: int) -> bool:
    return bool(state & 0x10)


RISKY_EXCLUSIONS = ("\\users\\", "\\temp", "\\tmp", "\\downloads", "\\appdata", "\\programdata")


def risky_exclusion(path: str) -> bool:
    p = path.lower().rstrip("\\")
    return len(p) <= 3 or "*" in p or any(r in p + "\\" for r in RISKY_EXCLUSIONS)


def collect_defender(ctx: Context) -> list[Note]:
    note = Note("Antivirus", AV_CAT, tags=["antivirus", "defender", "windows"])
    ctx.set_note(note.title)
    d = as_dict(ps_json(ctx, DEFENDER, category=AV_CAT, what="Antivirus status",
                        name="Defender status"))
    if not d:
        note.summary = "not collected"
        return [note]
    status = as_dict(d.get("Status"))
    products = [as_dict(p) for p in as_list(d.get("Products"))]
    others = [p for p in products if "defender" not in str(p.get("Name", "")).lower()]
    others_on = [p for p in others if _product_on(int(p.get("State") or 0))]
    defender_rt = bool(status.get("RealTime") and status.get("AntivirusEnabled"))
    mode = str(status.get("Mode") or "")

    note.add(md.heading("Installed antivirus products"), md.table(
        ("Product", "Real-time", "Definitions"),
        [(p.get("Name"), "on" if _product_on(int(p.get("State") or 0)) else "off",
          "out of date" if _product_outdated(int(p.get("State") or 0)) else "up to date")
         for p in products]))
    if d.get("StatusError"):
        ctx.gap("Microsoft Defender status", AV_CAT, GapKind.ERROR,
                str(d["StatusError"])[:200])
    elif status:
        note.add(md.heading("Microsoft Defender"), md.kv_table([
            ("Mode", mode), ("Real-time protection", "on" if status.get("RealTime") else "off"),
            ("Behavior monitoring", "on" if status.get("Behavior") else "off"),
            ("Tamper protection", "on" if status.get("TamperProtected") else "off"),
            ("Definitions age", f"{status.get('SignatureAgeDays')} day(s)"),
            ("Last quick scan", f"{status.get('QuickScanAgeDays')} day(s) ago"),
        ]))
    note.summary = ("Defender real-time on" if defender_rt else
                    f"{others_on[0].get('Name')} active" if others_on else
                    "no active real-time antivirus")
    if not defender_rt and not others_on:
        ctx.finding(
            "No active real-time antivirus", Severity.HIGH, AV_CAT,
            "Neither Microsoft Defender nor another registered antivirus product has "
            "real-time protection on, so malware is not blocked when it is downloaded or run.",
            "Windows Security → Virus & threat protection → Manage settings → Real-time "
            "protection: On. If a third-party product is installed, make sure it is running.",
            key="no-antivirus",
        )
    if defender_rt and int(status.get("SignatureAgeDays") or 0) > 7:
        ctx.finding(
            f"Defender definitions are {status.get('SignatureAgeDays')} days old",
            Severity.MEDIUM, AV_CAT,
            "Out-of-date definitions miss recent malware.",
            "Windows Security → Virus & threat protection → Protection updates → Check for "
            "updates; make sure Windows Update is not blocked.",
            key="defender-signatures",
        )
    if defender_rt and not status.get("TamperProtected"):
        ctx.finding(
            "Defender tamper protection is off", Severity.LOW, AV_CAT,
            "Tamper protection stops malware (and scripts) from turning Defender off or "
            "adding exclusions.",
            "Windows Security → Virus & threat protection → Manage settings → Tamper "
            "protection: On.",
            key="tamper-protection",
        )
    # Exclusions matter whenever Defender is the antivirus in charge, even if real-time
    # protection happens to be off right now (that is reported separately).
    defender_primary = bool(status.get("AntivirusEnabled")) and "Passive" not in mode
    _exclusions(ctx, note, as_dict(d.get("Preferences")), defender_primary)
    return [note]


def _exclusions(ctx: Context, note: Note, prefs: dict[str, Any], defender_primary: bool) -> None:
    if not prefs:
        return
    paths = [str(p) for p in as_list(prefs.get("ExclusionPath"))]
    procs = [str(p) for p in as_list(prefs.get("ExclusionProcess"))]
    exts = [str(p) for p in as_list(prefs.get("ExclusionExtension"))]
    hidden = any(x.startswith("N/A") for x in paths + procs + exts)
    if hidden:
        ctx.gap("Defender exclusions", AV_CAT, GapKind.NEEDS_ROOT,
                "Windows only shows exclusions to administrators")
        return
    rows = [("Path", p) for p in paths] + [("Process", p) for p in procs] + \
           [("Extension", p) for p in exts]
    note.add(md.heading("Defender exclusions"), md.table(("Type", "Excluded"), rows)
             if rows else "_None._")
    risky = [p for p in paths if risky_exclusion(p)] + \
            [e for e in exts if e.lstrip(".").lower() in ("exe", "dll", "ps1", "bat", "js", "vbs")]
    if risky and defender_primary:
        ctx.finding(
            "Broad Defender exclusions", Severity.MEDIUM, AV_CAT,
            "These exclusions cover locations or file types that malware commonly uses "
            "(user folders, downloads, temp, whole drives, executables). Anything placed there "
            "is never scanned; malware also adds exclusions like these.",
            "Remove them (Windows Security → Virus & threat protection → Exclusions), or narrow "
            "them to a specific file or folder you trust.",
            evidence="\n".join(risky), key="defender-exclusions",
        )
    elif rows:
        ctx.finding(f"{len(rows)} Defender exclusion(s) configured", Severity.INFO, AV_CAT,
                    "Excluded items are never scanned. Make sure you recognise each one.",
                    "Review them under Windows Security → Exclusions.",
                    evidence="\n".join(f"{t}: {x}" for t, x in rows), key="defender-exclusions")
    if int(prefs.get("PUAProtection") or 0) == 0 and defender_primary:
        ctx.finding("Potentially unwanted app blocking is off", Severity.INFO, AV_CAT,
                    "PUA protection blocks adware, bundleware and crypto-miners.",
                    "Windows Security → App & browser control → Reputation-based protection → "
                    "Potentially unwanted app blocking: On.", key="pua")
