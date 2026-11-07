"""Windows overview (version, support status) and hardware inventory."""

from __future__ import annotations

from datetime import date, datetime

from archaudit import md
from archaudit.collectors.windows._ps import as_dict, as_list, ps_json
from archaudit.core import Context, Note, Severity

CAT = "System"
LIFECYCLE_URL = "https://learn.microsoft.com/lifecycle/products/windows-11-home-and-pro"

# build -> (version, end of servicing Home/Pro, end of servicing Enterprise/Education).
# Source: Microsoft lifecycle pages; update when new feature updates ship.
WINDOWS_BUILDS: dict[int, tuple[str, date, date]] = {
    19045: ("Windows 10 22H2", date(2025, 10, 14), date(2025, 10, 14)),
    22000: ("Windows 11 21H2", date(2023, 10, 10), date(2024, 10, 8)),
    22621: ("Windows 11 22H2", date(2024, 10, 8), date(2025, 10, 14)),
    22631: ("Windows 11 23H2", date(2025, 11, 11), date(2026, 11, 10)),
    26100: ("Windows 11 24H2", date(2026, 10, 13), date(2027, 10, 12)),
    26200: ("Windows 11 25H2", date(2027, 10, 12), date(2028, 10, 10)),
}

OVERVIEW = r"""
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[pscustomobject]@{
    Caption        = [string]$os.Caption
    Version        = [string]$os.Version
    Build          = [int]$os.BuildNumber
    UBR            = Reg $cv 'UBR'
    DisplayVersion = Reg $cv 'DisplayVersion'
    EditionID      = Reg $cv 'EditionID'
    InstallDate    = $os.InstallDate.ToString('s')
    LastBoot       = $os.LastBootUpTime.ToString('s')
    Hostname       = $env:COMPUTERNAME
    Domain         = [string]$cs.Domain
    PartOfDomain   = [bool]$cs.PartOfDomain
    Architecture   = [string]$os.OSArchitecture
    TimeZone       = (Get-TimeZone).Id
    Locale         = (Get-Culture).Name
} | ConvertTo-Json -Compress
"""

HARDWARE = r"""
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
[pscustomobject]@{
    Manufacturer = [string]$cs.Manufacturer
    Model        = [string]$cs.Model
    MemoryBytes  = [int64]$cs.TotalPhysicalMemory
    SystemType   = [int]$cs.PCSystemType
    CPU          = [string]$cpu.Name
    CPUVendor    = [string]$cpu.Manufacturer
    Cores        = [int]$cpu.NumberOfCores
    Threads      = [int]$cpu.NumberOfLogicalProcessors
    MaxMHz       = [int]$cpu.MaxClockSpeed
    VirtFirmware = [bool]$cpu.VirtualizationFirmwareEnabled
    BIOSVendor   = [string]$bios.Manufacturer
    BIOSVersion  = [string]$bios.SMBIOSBIOSVersion
    BIOSDate     = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { $null }
    GPUs         = @(Get-CimInstance Win32_VideoController | ForEach-Object { [string]$_.Name })
    Batteries    = @(Get-CimInstance Win32_Battery | ForEach-Object {
                       [pscustomobject]@{ Name = [string]$_.Name; Charge = [int]$_.EstimatedChargeRemaining } })
    Disks        = @(Get-CimInstance Win32_DiskDrive | ForEach-Object {
                       [pscustomobject]@{ Model = [string]$_.Model; SizeGB = [math]::Round($_.Size / 1GB, 1);
                                          Interface = [string]$_.InterfaceType } })
} | ConvertTo-Json -Depth 4 -Compress
"""


def support_status(build: int, edition: str, today: date | None = None
                   ) -> tuple[str, date | None, bool]:
    """(version name, end of servicing, still supported) for a build/edition."""
    today = today or date.today()
    if build not in WINDOWS_BUILDS:
        return f"build {build}", None, True
    name, consumer, enterprise = WINDOWS_BUILDS[build]
    end = enterprise if any(e in edition for e in ("Enterprise", "Education")) else consumer
    return name, end, today <= end


def collect_overview(ctx: Context) -> list[Note]:
    note = Note("Overview", CAT, tags=["overview", "windows"])
    ctx.set_note(note.title)
    data = as_dict(ps_json(ctx, OVERVIEW, category=CAT, what="Windows version",
                           name="Win32_OperatingSystem"))
    hostname = str(data.get("Hostname") or "windows")
    caption = str(data.get("Caption") or "Windows")
    build = int(data.get("Build") or 0)
    edition = str(data.get("EditionID") or caption)
    ctx.facts |= {"hostname": hostname, "distro": caption,
                  "kernel": f"{data.get('Version', '')}.{data.get('UBR') or 0}".strip(".")}
    note.summary = f"{caption} {data.get('DisplayVersion') or ''} on {hostname}".replace("  ", " ")
    uptime = ""
    if boot := data.get("LastBoot"):
        try:
            delta = datetime.now() - datetime.fromisoformat(boot)
            uptime = f"{delta.days}d {delta.seconds // 3600}h"
        except ValueError:
            pass
    note.add(md.heading("Identity"), md.kv_table([
        ("Computer name", hostname),
        ("Windows", caption),
        ("Version", f"{data.get('DisplayVersion') or ''} (build {build}.{data.get('UBR') or 0})"),
        ("Edition", data.get("EditionID")),
        ("Architecture", data.get("Architecture")),
        ("Domain / workgroup", f"{data.get('Domain')} ({'domain' if data.get('PartOfDomain') else 'workgroup'})"),
        ("Installed", data.get("InstallDate")),
        ("Uptime", uptime),
        ("Time zone", data.get("TimeZone")),
        ("Locale", data.get("Locale")),
        ("Audit ran as administrator", "yes" if ctx.is_root else "no (some checks limited)"),
    ]))
    if build:
        _support(ctx, note, build, edition, caption)
    return [note]


def _support(ctx: Context, note: Note, build: int, edition: str, caption: str) -> None:
    if "LTSC" in edition or "LTSC" in caption or "Server" in caption:
        note.add(md.kv_table([("Support", "LTSC/Server: check its own lifecycle page")]))
        return
    name, end, supported = support_status(build, edition)
    note.add(md.kv_table([("Servicing ends", f"{end:%Y-%m-%d}" if end else "unknown build")]))
    if supported or end is None:
        return
    if build == 19045:
        ctx.finding(
            "Windows 10 is past end of support", Severity.MEDIUM, CAT,
            f"Windows 10 22H2 reached end of support on {end:%Y-%m-%d}. Only PCs enrolled in "
            "Extended Security Updates (ESU) still receive security fixes; check the Updates "
            "note to see whether this one does.",
            "Upgrade to Windows 11 if the hardware allows it, or enroll in ESU "
            "(Settings → Windows Update).",
            evidence=f"{caption}, build {build}", references=[LIFECYCLE_URL],
            key="os-support",
        )
        return
    ctx.finding(
        f"{name} no longer receives security updates", Severity.HIGH, CAT,
        f"Servicing for {name} ({edition}) ended on {end:%Y-%m-%d}. New Windows "
        "vulnerabilities are no longer patched on this version.",
        "Install the latest feature update: Settings → Windows Update → check for updates "
        "(or use the Windows 11 Installation Assistant).",
        evidence=f"{caption}, build {build}", references=[LIFECYCLE_URL], key="os-support",
    )


def collect_hardware(ctx: Context) -> list[Note]:
    note = Note("Hardware", CAT, tags=["hardware", "windows"])
    ctx.set_note(note.title)
    hw = as_dict(ps_json(ctx, HARDWARE, category=CAT, what="Hardware inventory",
                         name="hardware (CIM)"))
    if not hw:
        note.summary = "not collected"
        return [note]
    vendor = str(hw.get("CPUVendor") or "")
    ctx.facts["cpu_vendor"] = vendor
    batteries = as_list(hw.get("Batteries"))
    # PCSystemType 2 = mobile
    if batteries or hw.get("SystemType") == 2:
        ctx.facts["laptop"] = "yes"
    mem = int(hw.get("MemoryBytes") or 0) / 1024**3
    note.summary = f"{hw.get('CPU', 'unknown CPU')}, {mem:.1f} GiB RAM"
    note.add(
        md.heading("Machine"),
        md.kv_table([("Vendor", hw.get("Manufacturer")), ("Model", hw.get("Model")),
                     ("BIOS/UEFI", f"{hw.get('BIOSVendor')} {hw.get('BIOSVersion')} "
                                   f"({hw.get('BIOSDate')})"),
                     ("Virtualization enabled in firmware",
                      "yes" if hw.get("VirtFirmware") else "no")]),
        md.heading("CPU"),
        md.kv_table([("Model", hw.get("CPU")), ("Vendor", vendor), ("Cores", hw.get("Cores")),
                     ("Threads", hw.get("Threads")), ("Max MHz", hw.get("MaxMHz"))]),
        md.heading("Memory"), md.kv_table([("Total RAM", f"{mem:.1f} GiB")]),
        md.heading("Graphics"), md.bullet(as_list(hw.get("GPUs"))),
        md.heading("Disks"),
        md.table(("Model", "Size (GB)", "Interface"),
                 [(d.get("Model"), d.get("SizeGB"), d.get("Interface"))
                  for d in as_list(hw.get("Disks"))]),
    )
    if batteries:
        note.add(md.heading("Battery"), md.table(("Battery", "Charge"),
                                                 [(b.get("Name"), f"{b.get('Charge')}%")
                                                  for b in batteries]))
    return [note]
