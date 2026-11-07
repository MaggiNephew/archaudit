"""Security-relevant log analysis from the systemd journal (read-only)."""

from __future__ import annotations

import re
from collections import Counter

from archaudit import md
from archaudit.collectors._util import active
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Logs"
_SSH_FAIL = re.compile(r"(?:Failed \S+ for (?:invalid user )?(?P<u1>\S+)|Invalid user (?P<u2>\S+))"
                       r" from (?P<ip>[0-9a-fA-F:.]+)")
_SSH_OK = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
_PARTIAL_HINT = "not seeing messages from other users"


def _journal(ctx: Context, args: list[str], what: str, raw: str | None = None) -> str | None:
    res = ctx.cmd(["journalctl", "-q", "--no-pager", *args], category=CAT, what=what,
                  raw_name=raw, ok_codes=(0, 1), timeout=120)
    if res is None:
        return None
    if _PARTIAL_HINT in res.stderr and not ctx.is_root:
        ctx.gap(what, CAT, GapKind.NEEDS_ROOT,
                "only your own messages were visible",
                "Re-run with `sudo`, or add yourself to the `systemd-journal` group")
    return res.stdout


def collect_logs(ctx: Context) -> list[Note]:
    note = Note("Logs", CAT, tags=["logs", "journal"])
    ctx.set_note(note.title)
    if not ctx.has("journalctl"):
        ctx.gap("systemd journal", CAT, GapKind.NOT_PRESENT, "`journalctl` not found")
        note.summary = "journal not available"
        return [note]

    errors = _journal(ctx, ["-b", "-p", "3", "-o", "short-iso", "-n", "200"],
                      "Errors this boot", raw="journal errors")
    if errors is not None:
        lines = [ln for ln in errors.splitlines() if ln.strip()]
        note.add(md.heading(f"Errors this boot ({len(lines)} shown, max 200)"),
                 md.callout("example", "journalctl -b -p err", md.code(errors), folded=True))
    if kernel := _journal(ctx, ["-k", "-b", "-p", "4", "-o", "short-iso", "-n", "100"],
                          "Kernel warnings this boot"):
        note.add(md.callout("example", "Kernel warnings (journalctl -k -p warning)",
                            md.code(kernel), folded=True))

    ssh = _ssh_auth(ctx, note)
    _sudo_auth(ctx, note)
    _coredumps(ctx, note)

    usage = ctx.cmd(["journalctl", "--disk-usage"], category=CAT, what="Journal disk usage")
    auditd = active(ctx, ["auditd.service"])
    note.add(md.heading("Logging setup"),
             md.kv_table([("Journal size", usage.stdout.strip() if usage else ""),
                          ("Linux audit daemon (auditd)", "active" if auditd else "not running")]))
    note.summary = f"{ssh} failed SSH login attempt(s) in 30 days"
    return [note]


def _ssh_auth(ctx: Context, note: Note) -> int:
    text = _journal(ctx, ["-o", "cat", "--since", "-30d", "-u", "sshd.service",
                          "-u", "ssh.service"],
                    "SSH login attempts (30 days)")
    if not text:
        return 0
    failures: Counter[str] = Counter()
    users: Counter[str] = Counter()
    accepted = []
    for line in text.splitlines():
        if m := _SSH_FAIL.search(line):
            failures[m["ip"]] += 1
            users[m["u1"] or m["u2"]] += 1
        elif m := _SSH_OK.search(line):
            accepted.append((m["user"], m["ip"], m["method"]))
    total = sum(failures.values())
    note.add(md.heading("SSH authentication (last 30 days)"),
             md.kv_table([("Failed attempts", total), ("Distinct source IPs", len(failures)),
                          ("Successful logins", len(accepted))]),
             md.table(("Source IP", "Failures"), failures.most_common(15)) if failures else "",
             md.table(("User", "From", "Method"), accepted[-20:]) if accepted else "")
    if total >= 20:
        ctx.finding(
            f"SSH brute-force activity: {total} failed logins in 30 days", Severity.MEDIUM, CAT,
            f"{len(failures)} source address(es) tried to log in; most-targeted usernames: "
            + ", ".join(u for u, _ in users.most_common(5)) + ".",
            "Disable password authentication, restrict `AllowUsers`, and add `sshguard` or "
            "`fail2ban`; avoid exposing SSH to the internet if not required.",
            evidence="\n".join(f"{ip}: {n}" for ip, n in failures.most_common(10)),
            key="ssh-bruteforce",
        )
    if any(user == "root" for user, _, method in accepted if method == "password"):
        ctx.finding("Successful root login over SSH with a password", Severity.HIGH, CAT,
                    "Root logged in over SSH using a password in the last 30 days.",
                    "Verify these logins were you; set `PermitRootLogin no`.",
                    evidence="\n".join(f"{u} from {ip} ({m})" for u, ip, m in accepted
                                       if u == "root"))
    return total


def _sudo_auth(ctx: Context, note: Note) -> None:
    text = _journal(ctx, ["-o", "short-iso", "--since", "-30d", "_COMM=sudo"],
                    "sudo usage (30 days)")
    if not text:
        return
    bad = [ln for ln in text.splitlines() if "incorrect password" in ln]
    denied = [ln for ln in text.splitlines() if "NOT in sudoers" in ln]
    note.add(md.heading("sudo (last 30 days)"),
             md.kv_table([("sudo invocations logged", text.count("COMMAND=")),
                          ("Failed password attempts", len(bad)),
                          ("Denied (user not in sudoers)", len(denied))]))
    if denied or len(bad) >= 5:
        ctx.finding(
            "Failed or unauthorized sudo attempts", Severity.LOW, CAT,
            "Repeated wrong passwords or attempts by non-sudo users can indicate someone "
            "trying to escalate privileges.",
            "Review the entries and confirm they were you.",
            evidence="\n".join((denied + bad)[-15:]),
        )


def _coredumps(ctx: Context, note: Note) -> None:
    res = ctx.cmd(["coredumpctl", "list", "--no-pager", "-q", "--since", "-30d"],
                  category=CAT, what="Crash dumps", ok_codes=(0, 1), quiet_missing=True)
    if res and res.lines:
        note.add(md.heading(f"Crashes (last 30 days): {len(res.lines)}"),
                 md.callout("example", "coredumpctl list", md.code(res.stdout), folded=True))
