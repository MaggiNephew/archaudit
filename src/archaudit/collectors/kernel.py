"""Kernel, boot chain, CPU vulnerability mitigations and sysctl hardening."""

from __future__ import annotations

import platform
from dataclasses import dataclass

from archaudit import md
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Kernel & Boot"
SECURE_BOOT_VAR = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
KERNEL_PACKAGES = ("linux", "linux-lts", "linux-zen", "linux-hardened", "linux-rt")


@dataclass(frozen=True, slots=True)
class SysctlCheck:
    key: str
    expected: str          # human readable
    severity: Severity
    why: str

    def passes(self, value: str) -> bool:
        op, _, target = self.expected.partition(" ")
        try:
            v, t = int(value.split()[0]), int(target)
        except (ValueError, IndexError):
            return False
        return v >= t if op == ">=" else v == t


SYSCTL_CHECKS: tuple[SysctlCheck, ...] = (
    SysctlCheck("kernel.randomize_va_space", "== 2", Severity.HIGH, "full ASLR"),
    SysctlCheck("kernel.kptr_restrict", ">= 1", Severity.LOW, "hide kernel pointers"),
    SysctlCheck("kernel.dmesg_restrict", "== 1", Severity.LOW, "restrict kernel log to root"),
    SysctlCheck("kernel.unprivileged_bpf_disabled", ">= 1", Severity.MEDIUM,
                "block unprivileged eBPF (common LPE vector)"),
    SysctlCheck("kernel.yama.ptrace_scope", ">= 1", Severity.LOW,
                "processes cannot ptrace non-children"),
    SysctlCheck("kernel.kexec_load_disabled", "== 1", Severity.INFO,
                "prevent replacing the running kernel"),
    SysctlCheck("kernel.sysrq", "== 0", Severity.INFO, "disable magic SysRq (physical access)"),
    SysctlCheck("fs.protected_symlinks", "== 1", Severity.MEDIUM, "symlink race protection"),
    SysctlCheck("fs.protected_hardlinks", "== 1", Severity.MEDIUM, "hardlink race protection"),
    SysctlCheck("fs.protected_fifos", ">= 1", Severity.LOW, "FIFO race protection"),
    SysctlCheck("fs.protected_regular", ">= 1", Severity.LOW, "regular-file race protection"),
    SysctlCheck("fs.suid_dumpable", "== 0", Severity.LOW, "no core dumps from SUID programs"),
    SysctlCheck("net.ipv4.tcp_syncookies", "== 1", Severity.LOW, "SYN flood protection"),
    SysctlCheck("net.ipv4.conf.all.rp_filter", ">= 1", Severity.LOW, "reverse-path filtering"),
    SysctlCheck("net.ipv4.conf.all.accept_redirects", "== 0", Severity.LOW,
                "ignore ICMP redirects"),
    SysctlCheck("net.ipv4.conf.all.send_redirects", "== 0", Severity.LOW,
                "do not send ICMP redirects (not a router)"),
    SysctlCheck("net.ipv4.conf.all.accept_source_route", "== 0", Severity.LOW,
                "drop source-routed packets"),
    SysctlCheck("net.ipv6.conf.all.accept_redirects", "== 0", Severity.LOW,
                "ignore IPv6 redirects"),
)


def _sysctl_path(key: str) -> str:
    return "/proc/sys/" + key.replace(".", "/")


def _pacman_versions(ctx: Context, names: tuple[str, ...]) -> dict[str, str]:
    """Return {pkg: version} for installed packages among ``names``."""
    res = ctx.runner.run(["pacman", "-Q", *names], ctx.timeout, ok_codes=(0, 1))
    versions: dict[str, str] = {}
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2:
            versions[parts[0]] = parts[1]
    return versions


def collect_kernel(ctx: Context) -> list[Note]:
    note = Note("Kernel & Boot", CAT, tags=["kernel", "boot"])
    ctx.set_note(note.title)

    release = (ctx.read("/proc/sys/kernel/osrelease") or "").strip()
    if not release and str(ctx.root) == "/":
        release = platform.release()
    cmdline = (ctx.read("/proc/cmdline") or "").strip()
    installed = _pacman_versions(ctx, KERNEL_PACKAGES) if ctx.has("pacman") else {}
    module_dirs = ctx.listdir("/usr/lib/modules")
    tainted = (ctx.read("/proc/sys/kernel/tainted") or "0").strip()

    # Arch removes the old modules directory on kernel upgrade, so a running
    # release without a matching directory means "upgraded, not rebooted".
    if release and module_dirs and release not in module_dirs:
        ctx.finding(
            "Kernel upgraded but system not rebooted", Severity.MEDIUM, CAT,
            "The running kernel's modules are no longer installed. Security fixes in "
            "the new kernel are not active, and loading new modules will fail.",
            "Reboot to start the updated kernel.",
            evidence=f"running {release}; installed module dirs: {', '.join(module_dirs)}",
        )

    flags = cmdline.split()
    if "mitigations=off" in flags:
        ctx.finding(
            "CPU mitigations disabled on the kernel command line", Severity.HIGH, CAT,
            "`mitigations=off` turns off protections against Spectre, Meltdown, MDS, "
            "Retbleed and related CPU side-channel attacks.",
            "Remove `mitigations=off` from the bootloader configuration and regenerate it.",
            evidence=cmdline,
        )
    for bad in ("nopti", "nospectre_v1", "nospectre_v2", "nokaslr", "spectre_v2=off"):
        if bad in flags:
            ctx.finding(
                f"Kernel hardening disabled: {bad}", Severity.MEDIUM, CAT,
                f"The boot parameter `{bad}` disables a kernel security mitigation.",
                f"Remove `{bad}` from the kernel command line.", evidence=cmdline,
            )

    ctx.facts["kernel"] = release or "unknown"
    note.summary = f"running {release or 'unknown'}"
    note.add(
        md.heading("Kernel"),
        md.kv_table([
            ("Running release", release),
            ("Installed kernel packages",
             ", ".join(f"{k} {v}" for k, v in installed.items())),
            ("Module directories", ", ".join(module_dirs)),
            ("Loaded modules", str(len((ctx.read("/proc/modules") or "").splitlines()))),
            ("Taint flags", tainted if tainted != "0" else "0 (clean)"),
        ]),
        md.heading("Command line"), md.code(cmdline or "(unreadable)"),
    )

    _cpu_vulnerabilities(ctx, note)
    _microcode(ctx, note, installed_kernel=bool(installed))
    _security_modules(ctx, note)
    _boot(ctx, note)
    _sysctl(ctx, note)
    return [note]


def _cpu_vulnerabilities(ctx: Context, note: Note) -> None:
    base = "/sys/devices/system/cpu/vulnerabilities"
    names = ctx.listdir(base)
    if not names:
        ctx.gap("CPU vulnerability status", CAT, GapKind.NOT_PRESENT,
                f"`{base}` not available (container or very old kernel)")
        return
    rows, vulnerable = [], []
    for name in names:
        status = (ctx.read(f"{base}/{name}") or "").strip()
        if status.startswith("Vulnerable"):
            mark = "❌"
            vulnerable.append(f"{name}: {status}")
        elif status.startswith(("Not affected", "Mitigation")):
            mark = "✅"
        else:
            mark = "❔"
        rows.append((mark, name, status))
    note.add(md.heading("CPU vulnerability mitigations"),
             md.table(("", "Issue", "Kernel status"), rows))
    if vulnerable:
        ctx.finding(
            f"CPU vulnerable to {len(vulnerable)} side-channel issue(s)", Severity.HIGH, CAT,
            "The kernel reports these CPU vulnerabilities as unmitigated. Some can only be "
            "fixed with a microcode update; some require disabling SMT.",
            "Install the CPU microcode package (`intel-ucode` or `amd-ucode`), keep the "
            "kernel and firmware (BIOS/UEFI) updated, and do not boot with mitigations off.",
            evidence="\n".join(vulnerable),
            references=["https://docs.kernel.org/admin-guide/hw-vuln/index.html"],
            key="cpu-vulnerabilities",
        )


def _microcode(ctx: Context, note: Note, installed_kernel: bool) -> None:
    vendor = ctx.facts.get("cpu_vendor", "")
    if not vendor:
        for line in (ctx.read("/proc/cpuinfo") or "").splitlines():
            if line.startswith("vendor_id"):
                vendor = line.split(":", 1)[1].strip()
                break
    pkg = {"GenuineIntel": "intel-ucode", "AuthenticAMD": "amd-ucode"}.get(vendor)
    if not pkg or not ctx.has("pacman"):
        return
    present = pkg in _pacman_versions(ctx, (pkg,))
    note.add(md.heading("Microcode"),
             md.kv_table([("CPU vendor", vendor),
                          ("Microcode package",
                           f"{pkg} — {'installed' if present else 'MISSING'}")]))
    if not present and installed_kernel and "virtualized" not in ctx.facts:
        ctx.finding(
            f"CPU microcode package {pkg} not installed", Severity.MEDIUM, CAT,
            "Microcode updates fix CPU bugs and are required for several Spectre-class "
            "mitigations. Without the package, only the (often outdated) firmware "
            "microcode is used.",
            f"`sudo pacman -S {pkg}`, then make sure your bootloader loads it "
            "(mkinitcpio `microcode` hook or an initrd entry) and reboot.",
            references=["https://wiki.archlinux.org/title/Microcode"],
        )


def _security_modules(ctx: Context, note: Note) -> None:
    lsm = (ctx.read("/sys/kernel/security/lsm", category=CAT,
                    what="Active Linux Security Modules") or "").strip()
    lockdown = (ctx.read("/sys/kernel/security/lockdown") or "").strip()
    mac = [m for m in lsm.split(",") if m in ("apparmor", "selinux", "smack", "tomoyo")]
    note.add(md.heading("Security modules"),
             md.kv_table([("Active LSMs", lsm or "unknown"),
                          ("Mandatory access control", ", ".join(mac) or "none"),
                          ("Kernel lockdown", lockdown or "unknown")]))
    if lsm and not mac:
        ctx.finding(
            "No mandatory access control (AppArmor/SELinux) active", Severity.LOW, CAT,
            "Arch does not enable a MAC framework by default. AppArmor can confine "
            "network-facing and untrusted programs.",
            "Optional hardening: install `apparmor`, add `lsm=landlock,lockdown,yama,"
            "integrity,apparmor,bpf` to the kernel command line and enable "
            "`apparmor.service`.",
            references=["https://wiki.archlinux.org/title/AppArmor"],
        )


def _boot(ctx: Context, note: Note) -> None:
    uefi = ctx.exists("/sys/firmware/efi")
    secure_boot = "n/a (legacy BIOS)"
    if uefi:
        var = ctx.path(f"/sys/firmware/efi/efivars/{SECURE_BOOT_VAR}")
        try:
            data = var.read_bytes()
            secure_boot = "enabled" if data and data[-1] == 1 else "disabled"
        except FileNotFoundError:
            secure_boot = "unsupported by firmware"
        except PermissionError:
            secure_boot = "unknown"
            ctx.gap("Secure Boot state", CAT, GapKind.NEEDS_ROOT, "efivars not readable")
        except OSError:
            secure_boot = "unknown"
    loaders = []
    if ctx.exists("/boot/loader/loader.conf") or ctx.exists("/efi/loader/loader.conf"):
        loaders.append("systemd-boot")
    if ctx.exists("/boot/grub/grub.cfg"):
        loaders.append("GRUB")
    if ctx.exists("/boot/limine.conf") or ctx.exists("/boot/limine/limine.conf"):
        loaders.append("Limine")
    if ctx.listdir("/boot/EFI/Linux") or ctx.listdir("/efi/EFI/Linux"):
        loaders.append("UKI")
    note.add(md.heading("Boot"),
             md.kv_table([("Firmware", "UEFI" if uefi else "BIOS"),
                          ("Secure Boot", secure_boot),
                          ("Bootloader(s) detected", ", ".join(loaders) or "unknown")]))
    if secure_boot == "disabled":
        ctx.finding(
            "Secure Boot is disabled", Severity.LOW, CAT,
            "Without Secure Boot an attacker with physical or root access can tamper with "
            "the bootloader or kernel unnoticed. On Arch this requires enrolling your own "
            "keys, so it is common to leave it off.",
            "Optional: set up Secure Boot with `sbctl` and signed unified kernel images.",
            references=["https://wiki.archlinux.org/title/Unified_Extensible_Firmware_"
                        "Interface/Secure_Boot"],
        )
    if res := ctx.cmd(["bootctl", "status", "--no-pager"], category=CAT,
                      what="Bootloader status (bootctl)", raw_name="bootctl status",
                      ok_codes=(0, 1), quiet_missing=True):
        note.add(md.callout("example", "bootctl status", md.code(res.stdout), folded=True))


def _sysctl(ctx: Context, note: Note) -> None:
    rows, failing = [], []
    for check in SYSCTL_CHECKS:
        raw = ctx.read(_sysctl_path(check.key))
        if raw is None:
            rows.append(("❔", check.key, "unreadable/absent", check.expected, check.why))
            continue
        value = raw.strip()
        ok = check.passes(value)
        rows.append(("✅" if ok else "❌", check.key, value, check.expected, check.why))
        if not ok:
            failing.append((check, value))
    note.add(md.heading("Kernel hardening (sysctl)"),
             md.table(("", "Key", "Current", "Recommended", "Purpose"), rows))
    if not failing:
        return
    worst = max(c.severity for c, _ in failing)
    conf = "\n".join(f"{c.key} = {c.expected.split()[1]}" for c, _ in failing)
    ctx.finding(
        f"{len(failing)} kernel hardening setting(s) below recommendation", worst, CAT,
        "These sysctl values are weaker than common hardening baselines (KSPP, CIS).",
        "Review, then persist the values in `/etc/sysctl.d/99-hardening.conf` and run "
        "`sudo sysctl --system`:\n\n" + md.code(conf, "ini"),
        evidence="\n".join(f"{c.key} = {v} (want {c.expected})" for c, v in failing),
        references=["https://wiki.archlinux.org/title/Security#Kernel_hardening"],
        key="sysctl-hardening",
    )
