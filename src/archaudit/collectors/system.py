"""System overview and hardware inventory."""

from __future__ import annotations

import json
import os
import platform
import socket

from archaudit import md
from archaudit.core import Context, GapKind, Note, Severity

CAT = "System"


def parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def parse_kv(text: str, sep: str = "=") -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if sep in line:
            k, _, v = line.partition(sep)
            out[k.strip()] = v.strip()
    return out


def _fmt_duration(seconds: float) -> str:
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    return f"{days}d {hours}h {rem // 60}m"


def _kib_to_gib(value: str | None) -> str:
    if not value:
        return ""
    try:
        return f"{int(value.split()[0]) / 1024 / 1024:.1f} GiB"
    except (ValueError, IndexError):
        return value


def collect_overview(ctx: Context) -> list[Note]:
    note = Note("Overview", CAT, tags=["overview"])
    ctx.set_note(note.title)

    osr = parse_os_release(ctx.read("/etc/os-release", category=CAT, what="OS release",
                                    required=True) or "")
    distro_id = osr.get("ID", "unknown")
    family = ctx.platform.family
    ctx.facts["distro"] = osr.get("PRETTY_NAME", distro_id)
    ctx.facts["is_arch"] = "yes" if family == "arch" else "no"

    hostname = (ctx.read("/etc/hostname") or socket.gethostname()).strip()
    ctx.facts["hostname"] = hostname
    uname = platform.uname()

    uptime = ""
    if up := ctx.read("/proc/uptime"):
        uptime = _fmt_duration(float(up.split()[0]))
    load = " ".join((ctx.read("/proc/loadavg") or "").split()[:3])

    tz = ntp = ""
    if res := ctx.cmd(["timedatectl", "show"], category=CAT, what="Time & NTP status",
                      raw_name="timedatectl"):
        td = parse_kv(res.stdout)
        tz, ntp = td.get("Timezone", ""), td.get("NTPSynchronized", "")
        if td.get("NTP") == "no" or ntp == "no":
            ctx.finding(
                "Clock is not NTP-synchronized", Severity.LOW, CAT,
                "Accurate time matters for TLS validation, log correlation and "
                "Kerberos/TOTP. The system clock is not being synchronized.",
                "`sudo timedatectl set-ntp true` (uses systemd-timesyncd).",
                evidence=f"NTP={td.get('NTP')} NTPSynchronized={ntp}",
            )

    locale = parse_kv(ctx.read("/etc/locale.conf") or "").get("LANG", "")
    env = os.environ
    note.summary = f"{ctx.facts['distro']} on {hostname}, kernel {uname.release}"
    note.add(
        md.heading("Identity"),
        md.kv_table([
            ("Hostname", hostname),
            ("Distribution", ctx.facts["distro"]),
            ("Distribution family", family if family != "linux" else
             "**unknown** — generic Linux checks only"),
            ("Build ID", osr.get("BUILD_ID")),
            ("Kernel", uname.release),
            ("Architecture", uname.machine),
            ("Uptime", uptime),
            ("Load average (1/5/15)", load),
            ("Timezone", tz),
            ("NTP synchronized", ntp),
            ("Locale", locale),
            ("Desktop", env.get("XDG_CURRENT_DESKTOP")),
            ("Session type", env.get("XDG_SESSION_TYPE")),
            ("Audit ran as root", "yes" if ctx.is_root else "no (some checks limited)"),
        ]),
    )
    if family == "linux":
        note.add(md.callout("warning", "Unrecognised distribution",
                            "Supported families are Arch, Debian/Ubuntu and Fedora/RHEL. "
                            "Package checks may be missing or inaccurate."))
    return [note]


def collect_hardware(ctx: Context) -> list[Note]:
    note = Note("Hardware", CAT, tags=["hardware"])
    ctx.set_note(note.title)

    dmi_fields = ["sys_vendor", "product_name", "product_version", "board_vendor",
                  "board_name", "bios_vendor", "bios_version", "bios_date", "chassis_type"]
    dmi = {f: (ctx.read(f"/sys/class/dmi/id/{f}") or "").strip() for f in dmi_fields}

    cpu: dict[str, str] = {}
    if res := ctx.cmd(["lscpu", "-J"], category=CAT, what="CPU details (lscpu)",
                      raw_name="lscpu"):
        try:
            for entry in json.loads(res.stdout).get("lscpu", []):
                cpu[str(entry.get("field", "")).rstrip(":")] = str(entry.get("data", ""))
        except json.JSONDecodeError:
            ctx.gap("CPU details (lscpu)", CAT, GapKind.ERROR, "unparseable lscpu JSON")
    if not cpu and (info := ctx.read("/proc/cpuinfo")):
        first = info.split("\n\n")[0]
        kv = parse_kv(first, ":")
        cpu = {"Model name": kv.get("model name", ""), "Vendor ID": kv.get("vendor_id", "")}
    ctx.facts["cpu_vendor"] = cpu.get("Vendor ID", "")
    if cpu.get("Hypervisor vendor"):
        ctx.facts["virtualized"] = cpu["Hypervisor vendor"]

    meminfo = parse_kv(ctx.read("/proc/meminfo") or "", ":")
    note.summary = f"{cpu.get('Model name', 'unknown CPU')}, " \
                   f"{_kib_to_gib(meminfo.get('MemTotal'))} RAM"

    note.add(
        md.heading("Machine"),
        md.kv_table([
            ("Vendor", dmi["sys_vendor"]), ("Model", dmi["product_name"]),
            ("Version", dmi["product_version"]),
            ("Board", f"{dmi['board_vendor']} {dmi['board_name']}".strip()),
            ("BIOS/UEFI", f"{dmi['bios_vendor']} {dmi['bios_version']} ({dmi['bios_date']})"
             if dmi["bios_version"] else ""),
            ("Firmware type", "UEFI" if ctx.exists("/sys/firmware/efi") else "BIOS / legacy"),
            ("Virtualization", cpu.get("Hypervisor vendor")),
        ]),
        md.heading("CPU"),
        md.kv_table([(k, cpu.get(k)) for k in (
            "Model name", "Vendor ID", "Architecture", "CPU(s)", "Thread(s) per core",
            "Core(s) per socket", "Socket(s)", "CPU max MHz", "Virtualization",
            "L3 cache")]),
        md.heading("Memory"),
        md.kv_table([
            ("Total RAM", _kib_to_gib(meminfo.get("MemTotal"))),
            ("Available", _kib_to_gib(meminfo.get("MemAvailable"))),
            ("Swap total", _kib_to_gib(meminfo.get("SwapTotal"))),
            ("Swap free", _kib_to_gib(meminfo.get("SwapFree"))),
        ]),
    )

    if res := ctx.cmd(["lspci"], category=CAT, what="PCI devices (lspci)", raw_name="lspci"):
        gpus = [ln.split(": ", 1)[-1] for ln in res.lines
                if any(k in ln for k in ("VGA", "3D controller", "Display controller"))]
        note.add(md.heading("Graphics"), md.bullet(gpus),
                 md.heading("PCI devices"), md.code(res.stdout))
    if res := ctx.cmd(["lsusb"], category=CAT, what="USB devices (lsusb)", raw_name="lsusb"):
        note.add(md.heading("USB devices"), md.code(res.stdout))

    batteries = [b for b in ctx.listdir("/sys/class/power_supply") if b.startswith("BAT")]
    if batteries:
        ctx.facts["laptop"] = "yes"
        rows = []
        for bat in batteries:
            base = f"/sys/class/power_supply/{bat}"
            full = (ctx.read(f"{base}/energy_full")
                    or ctx.read(f"{base}/charge_full") or "").strip()
            design = (ctx.read(f"{base}/energy_full_design")
                      or ctx.read(f"{base}/charge_full_design") or "").strip()
            health = f"{100 * int(full) / int(design):.0f}%" if full.isdigit() and \
                design.isdigit() and int(design) else ""
            rows.append((bat, (ctx.read(f"{base}/status") or "").strip(),
                         (ctx.read(f"{base}/capacity") or "").strip() + "%",
                         health, (ctx.read(f"{base}/cycle_count") or "").strip()))
        note.add(md.heading("Battery"),
                 md.table(("Battery", "Status", "Charge", "Health", "Cycles"), rows))
    return [note]
