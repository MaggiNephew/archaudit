"""Storage, encryption, mount hardening and dangerous file permissions."""

from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Iterator
from typing import Any

from archaudit import md
from archaudit.collectors._pkg import NOT_OWNED, owners
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Filesystem"
REAL_FS = {"ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "vfat", "exfat", "zfs",
           "bcachefs", "jfs", "reiserfs", "ntfs3", "fuseblk"}

# SUID/SGID binaries shipped by common Arch, Debian/Ubuntu and Fedora packages.
# (Files owned by a package are reported with that package either way; this
# list only decides what counts as "not on the known list".)
KNOWN_SUID = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh", "/usr/bin/chfn",
    "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/pkexec", "/usr/bin/fusermount", "/usr/bin/fusermount3", "/usr/bin/expiry",
    "/usr/bin/chage", "/usr/bin/sg", "/usr/bin/newuidmap", "/usr/bin/newgidmap",
    "/usr/bin/unix_chkpwd", "/usr/bin/write", "/usr/bin/wall", "/usr/bin/crontab",
    "/usr/bin/ksu", "/usr/bin/vmware-user-suid-wrapper", "/usr/bin/Xorg.wrap",
    "/usr/bin/mount.cifs", "/usr/bin/mount.nfs", "/usr/bin/ssh-keysign",
    "/usr/bin/groupmems", "/usr/bin/doas", "/usr/bin/firejail", "/usr/bin/bwrap",
    "/usr/bin/ping", "/usr/bin/traceroute", "/usr/bin/at", "/usr/bin/beep",
    "/usr/lib/polkit-1/polkit-agent-helper-1", "/usr/lib/ssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/lib/Xorg.wrap",
    "/usr/lib/chromium/chrome-sandbox", "/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper",
    "/usr/lib/utempter/utempter", "/usr/lib/virtualbox/VBoxHeadless",
    "/usr/lib/virtualbox/VirtualBoxVM", "/usr/lib/virtualbox/VBoxNetAdpCtl",
    "/usr/lib/virtualbox/VBoxNetDHCP", "/usr/lib/virtualbox/VBoxNetNAT",
    "/usr/lib/virtualbox/VBoxSDL", "/usr/bin/sudoedit", "/usr/bin/screen",
    "/usr/bin/cardmgr", "/usr/lib/opensmtpd/smtpctl",
    # Debian / Ubuntu
    "/usr/lib/openssh/ssh-keysign", "/usr/lib/eject/dmcrypt-get-device",
    "/usr/lib/policykit-1/polkit-agent-helper-1", "/usr/sbin/pppd", "/usr/sbin/unix_chkpwd",
    "/usr/bin/ssh-agent", "/usr/bin/dotlockfile", "/usr/bin/bsd-write", "/usr/bin/ntfs-3g",
    "/usr/lib/snapd/snap-confine", "/usr/lib/x86_64-linux-gnu/utempter/utempter",
    "/usr/sbin/mount.nfs", "/usr/sbin/mount.cifs", "/usr/lib/xorg/Xorg.wrap",
    "/usr/sbin/pam_extrausers_chkpwd",
    # Fedora / RHEL
    "/usr/libexec/openssh/ssh-keysign", "/usr/libexec/polkit-1/polkit-agent-helper-1",
    "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
    "/usr/sbin/pam_timestamp_check", "/usr/sbin/userhelper", "/usr/sbin/grub2-set-bootflag",
    "/usr/libexec/utempter/utempter", "/usr/libexec/Xorg.wrap", "/usr/bin/vmware-user",
    "/usr/libexec/qemu-bridge-helper",
    "/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper",
}
SUID_SCAN_ROOTS = ("/usr/bin", "/usr/lib", "/usr/local", "/opt", "/home", "/tmp", "/var/tmp",
                   "/srv")
WRITABLE_SCAN_ROOTS = ("/etc", "/usr", "/boot", "/opt")
HARDENED_MOUNTS = {"/tmp": ("nosuid", "nodev"), "/dev/shm": ("nosuid", "nodev", "noexec"),
                   "/var/tmp": ("nosuid", "nodev"), "/home": ("nosuid", "nodev")}
MAX_REPORTED = 200


def _walk(ctx: Context, top: str) -> Iterator[tuple[str, os.stat_result]]:
    """Yield (path, lstat) for every entry under ``top`` on the same filesystem."""
    base = ctx.path(top)
    try:
        dev = base.stat().st_dev
    except OSError:
        return
    stack = [str(base)]
    prefix = str(ctx.root).rstrip("/")
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError:
            continue
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode) and st.st_dev == dev:
                stack.append(entry.path)
            rel = entry.path[len(prefix):] if prefix else entry.path
            yield rel or "/", st


def _flatten_lsblk(devices: list[dict[str, Any]], parent: list[str] | None = None,
                   depth: int = 0) -> Iterator[tuple[int, dict[str, Any], list[str]]]:
    for dev in devices:
        chain = [*(parent or []), str(dev.get("type", ""))]
        yield depth, dev, chain
        yield from _flatten_lsblk(dev.get("children") or [], chain, depth + 1)


def _mountpoints(dev: dict[str, Any]) -> list[str]:
    mps = dev.get("mountpoints") or [dev.get("mountpoint")]
    return [m for m in mps if m]


def collect_filesystem(ctx: Context) -> list[Note]:
    note = Note("Storage & Filesystems", CAT, tags=["storage", "filesystem", "encryption"])
    ctx.set_note(note.title)
    _storage(ctx, note)
    _mounts(ctx, note)
    perms = Note("File Permissions", CAT, tags=["filesystem", "permissions", "suid"])
    ctx.set_note(perms.title)
    _suid(ctx, perms)
    _world_writable(ctx, perms)
    return [note, perms]


def _storage(ctx: Context, note: Note) -> None:
    res = ctx.cmd(["lsblk", "-J", "-o", "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,RO,RM"],
                  category=CAT, what="Block devices (lsblk)", raw_name="lsblk")
    if res is None:
        return
    try:
        devices = json.loads(res.stdout).get("blockdevices", [])
    except json.JSONDecodeError:
        ctx.gap("Block devices (lsblk)", CAT, GapKind.ERROR, "unparseable lsblk JSON")
        return
    rows = []
    root_chain: list[str] | None = None
    for depth, dev, chain in _flatten_lsblk(devices):
        mps = _mountpoints(dev)
        rows.append(("　" * depth + ("└ " if depth else "") + str(dev.get("name")),
                     dev.get("type"), dev.get("size"), dev.get("fstype") or "",
                     ", ".join(mps), dev.get("model") or ""))
        if "/" in mps:
            root_chain = chain
    note.add(md.heading("Block devices"),
             md.table(("Device", "Type", "Size", "FS", "Mounted on", "Model"), rows))

    encrypted = root_chain is not None and "crypt" in root_chain
    ctx.facts["root_encrypted"] = "yes" if encrypted else ("no" if root_chain else "unknown")
    note.add(md.kv_table([("Root filesystem encrypted (LUKS/dm-crypt)",
                           ctx.facts["root_encrypted"])]))
    disks = sum(1 for d in devices if d.get("type") == "disk")
    note.summary = f"{disks} disk(s), root encrypted: {ctx.facts['root_encrypted']}"
    if root_chain is not None and not encrypted:
        laptop = ctx.facts.get("laptop") == "yes"
        ctx.finding(
            "Root filesystem is not encrypted",
            Severity.MEDIUM if laptop else Severity.LOW, CAT,
            "Anyone with physical access to the disk (theft, repair shop, disposal) can read "
            "all data, including SSH keys, browser sessions and password stores."
            + (" This machine has a battery, so it is likely portable." if laptop else ""),
            "Full-disk encryption must be set up at install time or by migrating data; see "
            "the wiki. At minimum, encrypt sensitive directories and swap.",
            references=["https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system"],
        )

    usage: list[tuple[str, str, str, str]] = []
    full: list[str] = []
    for line in (ctx.read("/proc/mounts") or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] not in REAL_FS:
            continue
        if sys.platform == "win32":  # this collector only runs on Linux
            break
        try:
            sv = os.statvfs(ctx.path(parts[1]))
        except OSError:
            continue
        total = sv.f_blocks * sv.f_frsize
        if not total:
            continue
        used = 100 * (1 - sv.f_bavail / sv.f_blocks)
        usage.append((parts[1], parts[2], f"{total / 1024**3:.1f} GiB", f"{used:.0f}%"))
        if used >= 90:
            full.append(f"{parts[1]}: {used:.0f}% used")
    note.add(md.heading("Disk usage"), md.table(("Mount", "FS", "Size", "Used"), usage))
    if full:
        ctx.finding("Filesystem nearly full", Severity.LOW, CAT,
                    "Full disks break updates (partial upgrades), logging and databases.",
                    "Free space: clear the package cache (`sudo paccache -rk2` / "
                    "`sudo apt clean` / `sudo dnf clean packages`), "
                    "`sudo journalctl --vacuum-size=200M`, remove unneeded packages.",
                    evidence="\n".join(full))


def _mounts(ctx: Context, note: Note) -> None:
    mounts: dict[str, set[str]] = {}
    for line in (ctx.read("/proc/mounts") or "").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            mounts[parts[1]] = set(parts[3].split(","))
    rows, weak = [], []
    for mp, wanted in HARDENED_MOUNTS.items():
        if mp not in mounts:
            rows.append((mp, "not a separate mount", ", ".join(wanted), "—"))
            continue
        missing = [o for o in wanted if o not in mounts[mp]]
        rows.append((mp, "mounted", ", ".join(wanted), ", ".join(missing) or "✅ none"))
        if missing:
            weak.append(f"{mp}: missing {', '.join(missing)}")
    note.add(md.heading("Mount hardening"),
             md.table(("Mount", "Status", "Recommended options", "Missing"), rows))
    if weak:
        ctx.finding("Temporary/shared mounts lack hardening options", Severity.LOW, CAT,
                    "`nosuid`/`nodev`/`noexec` on world-writable mounts limit what an attacker "
                    "can do with files dropped there.",
                    "Add the options in `/etc/fstab` (or a systemd mount drop-in for /tmp) "
                    "and remount.", evidence="\n".join(weak))

    swaps = [ln.split()[0] for ln in (ctx.read("/proc/swaps") or "").splitlines()[1:] if ln]
    note.add(md.kv_table([("Swap devices", ", ".join(swaps) or "none")]))
    if ctx.exists("/sys/firmware/efi"):
        try:
            mode = stat.S_IMODE(ctx.path("/boot").stat().st_mode)
            if ctx.path("/boot/loader").exists() and mode & 0o007:
                ctx.finding("/boot (EFI partition) is world-accessible", Severity.LOW, CAT,
                            "systemd-boot stores its random seed on the ESP; other users "
                            "should not be able to read it.",
                            "Mount the ESP with `fmask=0077,dmask=0077` in `/etc/fstab`.",
                            evidence=f"/boot mode {oct(mode)}")
        except OSError:
            pass


def _suid(ctx: Context, note: Note) -> None:
    roots = ("/",) if ctx.deep else SUID_SCAN_ROOTS
    found: list[tuple[str, str, str]] = []
    for top in roots:
        for path, st in _walk(ctx, top):
            if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                kind = "SUID" if st.st_mode & stat.S_ISUID else "SGID"
                found.append((path, kind, stat.filemode(st.st_mode)))
    found = sorted(set(found))
    unknown = [f for f in found if f[0] not in KNOWN_SUID]
    owned_by = owners(ctx, [f[0] for f in unknown])
    risky_dirs = ("/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/srv/")

    rows: list[tuple[str, str, str, str]] = []
    for path, kind, mode in found:
        status = "known" if path in KNOWN_SUID else owned_by.get(path, "unknown")
        rows.append((path, kind, mode, status))
    note.summary = f"{len(found)} SUID/SGID files, {len(unknown)} not on the known list"
    note.add(md.heading("SUID / SGID executables"),
             md.callout("abstract", "Scope", "Scanned: " + ", ".join(roots)
                        + (" (use `--deep` for the whole filesystem)" if not ctx.deep else "")),
             md.table(("Path", "Type", "Mode", "Owner package"), rows))

    in_risky = [f"{p} ({k})" for p, k, _ in found if p.startswith(risky_dirs)]
    if in_risky:
        ctx.finding("SUID/SGID executables in user-writable locations", Severity.HIGH, CAT,
                    "Privileged executables in home or temp directories are a classic "
                    "privilege-escalation backdoor.",
                    "Investigate each file; remove the bit with `sudo chmod u-s,g-s <file>` or "
                    "delete it.", evidence="\n".join(in_risky))
    unowned = [p for p, _, _ in found if owned_by.get(p) == NOT_OWNED
               and not p.startswith(risky_dirs)]
    if unowned:
        ctx.finding("SUID/SGID executables not owned by any package", Severity.MEDIUM, CAT,
                    "These privileged binaries were not installed by the package manager, so "
                    "nothing keeps them updated or verifies their integrity.",
                    "Confirm their origin; remove the SUID bit or the file if not needed.",
                    evidence="\n".join(unowned))


def _world_writable(ctx: Context, note: Note) -> None:
    roots = (*WRITABLE_SCAN_ROOTS, "/var", "/srv") if ctx.deep else WRITABLE_SCAN_ROOTS
    files, dirs = [], []
    for top in roots:
        for path, st in _walk(ctx, top):
            mode = st.st_mode
            if not mode & stat.S_IWOTH:
                continue
            if stat.S_ISREG(mode):
                files.append(f"{stat.filemode(mode)} {path}")
            elif stat.S_ISDIR(mode) and not mode & stat.S_ISVTX:
                dirs.append(f"{stat.filemode(mode)} {path}")
    note.add(md.heading("World-writable files and directories"),
             md.callout("abstract", "Scope", "Scanned: " + ", ".join(roots)),
             md.kv_table([("World-writable files", len(files)),
                          ("World-writable dirs without sticky bit", len(dirs))]),
             md.code("\n".join((files + dirs)[:MAX_REPORTED])) if files or dirs else "")
    if files:
        ctx.finding("World-writable files in system directories", Severity.HIGH, CAT,
                    "Any local user or compromised service can modify these files - if they are "
                    "configs or executables, that is privilege escalation.",
                    "`sudo chmod o-w <file>`; reinstall the owning package if unsure.",
                    evidence="\n".join(files[:50]))
    if dirs:
        ctx.finding("World-writable directories without sticky bit", Severity.MEDIUM, CAT,
                    "Any user can delete or replace other users' files in these directories.",
                    "`sudo chmod o-w <dir>` or `sudo chmod +t <dir>`.",
                    evidence="\n".join(dirs[:50]))
