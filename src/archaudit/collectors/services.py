"""systemd services, timers and scheduled jobs."""

from __future__ import annotations

from archaudit import md
from archaudit.collectors._util import unit_states
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Services"

LEGACY_INSECURE = {
    "telnet.socket": Severity.HIGH, "telnetd.socket": Severity.HIGH,
    "rsh.socket": Severity.HIGH, "rlogin.socket": Severity.HIGH, "rexec.socket": Severity.HIGH,
    "tftpd.socket": Severity.MEDIUM, "tftpd.service": Severity.MEDIUM,
    "vsftpd.service": Severity.LOW, "xinetd.service": Severity.LOW,
}


def _split_units(lines: list[str], fields: int) -> list[list[str]]:
    rows = []
    for line in lines:
        parts = line.split(None, fields - 1)
        if len(parts) >= 2:
            rows.append(parts + [""] * (fields - len(parts)))
    return rows


def collect_services(ctx: Context) -> list[Note]:
    note = Note("Services", CAT, tags=["services", "systemd"])
    ctx.set_note(note.title)
    if not ctx.has("systemctl"):
        ctx.gap("systemd services", CAT, GapKind.NOT_PRESENT, "`systemctl` not found")
        note.summary = "systemd not available"
        return [note]

    base = ["--no-legend", "--plain", "--no-pager"]
    running = ctx.cmd(["systemctl", "list-units", "--type=service", "--state=running", *base],
                      category=CAT, what="Running services", raw_name="running services")
    failed = ctx.cmd(["systemctl", "list-units", "--state=failed", *base],
                     category=CAT, what="Failed units")
    enabled = ctx.cmd(["systemctl", "list-unit-files", "--state=enabled", "--no-legend",
                       "--no-pager"], category=CAT, what="Enabled unit files")
    timers = ctx.cmd(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"],
                     category=CAT, what="Timers", raw_name="timers")

    run_rows = _split_units(running.lines, 5) if running else []
    failed_rows = _split_units(failed.lines, 5) if failed else []
    enabled_rows = _split_units(enabled.lines, 3) if enabled else []
    note.summary = f"{len(run_rows)} running, {len(failed_rows)} failed, " \
                   f"{len(enabled_rows)} enabled"

    note.add(md.heading("Failed units"),
             md.table(("Unit", "Description"), [(r[0], r[4]) for r in failed_rows])
             if failed_rows else md.callout("success", "No failed units"))
    note.add(md.heading("Running services"),
             md.table(("Unit", "Description"), [(r[0], r[4]) for r in run_rows]))
    note.add(md.heading("Enabled at boot"),
             md.callout("example", f"{len(enabled_rows)} enabled unit files",
                        md.table(("Unit", "State", "Preset"), enabled_rows), folded=True))
    if timers:
        note.add(md.heading("Timers"), md.code(timers.stdout))

    if failed_rows:
        ctx.finding(
            f"{len(failed_rows)} systemd unit(s) in failed state", Severity.LOW, CAT,
            "Failed units can mean a security service (firewall, update timer, backup) is "
            "silently not running.",
            "Inspect with `systemctl status <unit>` and `journalctl -u <unit> -b`.",
            evidence="\n".join(r[0] for r in failed_rows),
            key="failed-units",
        )

    states = unit_states(ctx, list(LEGACY_INSECURE))
    for unit, state in states.items():
        if state == "active":
            ctx.finding(
                f"Legacy/insecure network service active: {unit}", LEGACY_INSECURE[unit], CAT,
                f"`{unit}` provides a cleartext or legacy network service.",
                f"`sudo systemctl disable --now {unit}` and use SSH/SFTP instead.",
            )

    _cron(ctx, note)
    return [note]


def _cron(ctx: Context, note: Note) -> None:
    entries = []
    for path in ["/etc/crontab", *(f"/etc/cron.d/{n}" for n in ctx.listdir("/etc/cron.d"))]:
        if text := ctx.read(path):
            entries += [(path, ln.strip()) for ln in text.splitlines()
                        if ln.strip() and not ln.lstrip().startswith("#")]
    spool = ctx.listdir("/var/spool/cron")
    if ctx.exists("/var/spool/cron") and not spool and not ctx.is_root:
        ctx.gap("Per-user crontabs", CAT, GapKind.NEEDS_ROOT, "`/var/spool/cron` is root-only")
    if entries or spool:
        note.add(md.heading("Cron"), md.table(("File", "Entry"), entries),
                 md.kv_table([("User crontabs", ", ".join(spool) or "none")]))
