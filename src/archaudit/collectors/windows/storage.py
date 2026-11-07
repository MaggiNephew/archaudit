"""BitLocker / device encryption, disk usage, and writable system PATH folders."""

from __future__ import annotations

from typing import Any

from archaudit import md
from archaudit.collectors.windows._ps import WEAK_ACL, as_dict, as_list, denied, ps_json
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Filesystem"

STORAGE = WEAK_ACL + r"""
$bitlocker = $null; $bitlockerError = $null
try {
    $bitlocker = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Mount = [string]$_.MountPoint; Type = [string]$_.VolumeType
                           Protection = [string]$_.ProtectionStatus; Status = [string]$_.VolumeStatus
                           Percent = [double]$_.EncryptionPercentage; Method = [string]$_.EncryptionMethod
                           Protectors = (@($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType }) -join ', ') } })
} catch { $bitlockerError = $_.Exception.Message }
# Works without admin rights: 1 = protection on, 2 = off (other values: in progress/suspended)
$shellState = $null
try { $shellState = (New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch { }
$pathDirs = @(([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') | Where-Object { $_ } | ForEach-Object {
    $dir = [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\')
    if (Test-Path -LiteralPath $dir) { [pscustomobject]@{ Dir = $dir; Exists = $true; Weak = (WeakAcl $dir $true) } }
    else { $parent = Split-Path -Parent $dir
           [pscustomobject]@{ Dir = $dir; Exists = $false
                              Weak = if ($parent -and (Test-Path -LiteralPath $parent)) { WeakAcl $parent $true } else { $null } } } })
[pscustomobject]@{
    SystemDrive = $env:SystemDrive; BitLocker = $bitlocker; BitLockerError = $bitlockerError; ShellState = $shellState
    Disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [pscustomobject]@{ Drive = [string]$_.DeviceID; FS = [string]$_.FileSystem; Size = [int64]$_.Size; Free = [int64]$_.FreeSpace } })
    PathDirs = $pathDirs
} | ConvertTo-Json -Depth 4 -Compress
"""


def collect_storage(ctx: Context) -> list[Note]:
    note = Note("Storage & Encryption", CAT, tags=["storage", "encryption", "bitlocker",
                                                   "windows"])
    ctx.set_note(note.title)
    d = as_dict(ps_json(ctx, STORAGE, category=CAT, what="Storage and encryption",
                        name="storage"))
    if not d:
        note.summary = "not collected"
        return [note]
    _encryption(ctx, note, d)
    _disks(ctx, note, [as_dict(x) for x in as_list(d.get("Disks"))])
    _path_dirs(ctx, note, [as_dict(x) for x in as_list(d.get("PathDirs"))])
    return [note]


def _encryption(ctx: Context, note: Note, d: dict[str, Any]) -> None:
    system = str(d.get("SystemDrive") or "C:").upper()
    volumes = [as_dict(v) for v in as_list(d.get("BitLocker"))]
    state = "unknown"
    if volumes:
        note.add(md.heading("BitLocker"), md.table(
            ("Drive", "Type", "Protection", "Status", "Encrypted", "Method", "Key protectors"),
            [(v.get("Mount"), v.get("Type"), v.get("Protection"), v.get("Status"),
              f"{v.get('Percent')}%", v.get("Method"), v.get("Protectors")) for v in volumes]))
        sysvol = next((v for v in volumes if str(v.get("Mount", "")).upper() == system), {})
        if sysvol.get("Protection") == "On":
            state = "yes"
        elif str(sysvol.get("Status")) in ("FullyEncrypted", "EncryptionInProgress"):
            state = "suspended"
        elif sysvol:
            state = "no"
    else:
        if err := d.get("BitLockerError"):
            if denied(err) or not ctx.is_root:
                ctx.gap("BitLocker details", CAT, GapKind.NEEDS_ROOT,
                        "Get-BitLockerVolume needs administrator rights; used the Explorer "
                        "protection state instead")
            else:  # e.g. Home edition without the BitLocker module
                ctx.gap("BitLocker details", CAT, GapKind.NOT_PRESENT, str(err)[:200])
        shell = d.get("ShellState")
        state = {1: "yes", 2: "no"}.get(shell, "unknown") if isinstance(shell, int) else "unknown"
        note.add(md.heading("Device encryption"),
                 md.kv_table([(f"{system} BitLocker protection (Explorer)",
                               {"yes": "on", "no": "off"}.get(state, f"unknown ({shell})"))]))
    ctx.facts["root_encrypted"] = state
    note.summary = f"system drive encrypted: {state}"
    laptop = ctx.facts.get("laptop") == "yes"
    if state == "no":
        ctx.finding(
            "System drive is not encrypted", Severity.MEDIUM if laptop else Severity.LOW, CAT,
            "Anyone with physical access to the disk (theft, repair shop, disposal) can read "
            "all files, saved browser sessions and credentials."
            + (" This is a portable device." if laptop else ""),
            "Turn on BitLocker (Pro/Enterprise: Control Panel → BitLocker Drive Encryption) or "
            "Device encryption (Home: Settings → Privacy & security → Device encryption). Save "
            "the recovery key somewhere other than this PC.",
            key="disk-encryption",
        )
    elif state == "suspended":
        ctx.finding(
            "BitLocker protection is suspended", Severity.MEDIUM, CAT,
            "The drive is encrypted but the key is stored in the clear on disk, so the data is "
            "readable without unlocking. Windows suspends protection during some updates; it "
            "should resume after a restart.",
            "`manage-bde -protectors -enable C:` from an administrator prompt (or Resume "
            "protection in the BitLocker control panel).", key="bitlocker-suspended",
        )


def _disks(ctx: Context, note: Note, disks: list[dict[str, Any]]) -> None:
    rows, full = [], []
    for disk in disks:
        size, free = int(disk.get("Size") or 0), int(disk.get("Free") or 0)
        used = 100 * (1 - free / size) if size else 0
        rows.append((disk.get("Drive"), disk.get("FS"), f"{size / 1024**3:.1f} GiB",
                     f"{used:.0f}%"))
        if used >= 90:
            full.append(f"{disk.get('Drive')}: {used:.0f}% used")
    note.add(md.heading("Disk usage"), md.table(("Drive", "FS", "Size", "Used"), rows))
    if full:
        ctx.finding("Drive nearly full", Severity.LOW, CAT,
                    "Full drives make Windows updates fail and break logging.",
                    "Free space with Settings → System → Storage → Cleanup recommendations.",
                    evidence="\n".join(full), key="disk-full")


def _path_dirs(ctx: Context, note: Note, dirs: list[dict[str, Any]]) -> None:
    note.add(md.heading("System PATH folders"),
             md.table(("Folder", "Exists", "Writable by non-admins"),
                      [(x.get("Dir"), "yes" if x.get("Exists") else "**no**",
                        x.get("Weak") or "no") for x in dirs]))
    weak = [f"{x.get('Dir')} — {x.get('Weak')}" for x in dirs if x.get("Exists") and x.get("Weak")]
    plantable = [f"{x.get('Dir')} (missing; parent allows creating it: {x.get('Weak')})"
                 for x in dirs if not x.get("Exists") and x.get("Weak")]
    if weak or plantable:
        ctx.finding(
            "Writable folder in the system PATH", Severity.HIGH, CAT,
            "Programs running as SYSTEM search the machine PATH for executables and DLLs. A "
            "folder there that standard users can write to (or create) lets them plant a file "
            "that a privileged process loads: local privilege escalation.",
            "Remove write access for Users/Authenticated Users with `icacls`, delete PATH "
            "entries for folders that no longer exist (System Properties → Environment "
            "Variables), or move the tool into Program Files.",
            evidence="\n".join(weak + plantable), key="writable-path",
        )
