"""Accounts, groups, privilege (sudo/wheel/docker), password state and logins.

Password hashes are never copied into the report - only their *type* and
whether an account is locked or has an empty password.
"""

from __future__ import annotations

import re
import stat
from dataclasses import dataclass

from archaudit import md
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Users & Access"
NOLOGIN_SHELLS = ("/usr/bin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false",
                  "/usr/sbin/nologin", "/bin/nologin")
# Group membership that is effectively root.
PRIVILEGED_GROUPS = {
    "wheel": (Severity.INFO, "can use sudo (if enabled in sudoers)"),
    "docker": (Severity.MEDIUM, "can start privileged containers = root without a password"),
    "libvirt": (Severity.LOW, "can manage VMs and host devices"),
    "disk": (Severity.HIGH, "raw read/write access to disks"),
    "lxd": (Severity.MEDIUM, "can start privileged containers"),
}
HASH_TYPES = {"$y$": "yescrypt", "$gy$": "gost-yescrypt", "$7$": "scrypt", "$6$": "SHA-512",
              "$5$": "SHA-256", "$2b$": "bcrypt", "$2y$": "bcrypt", "$2a$": "bcrypt",
              "$1$": "MD5 (weak)"}


@dataclass(frozen=True, slots=True)
class Account:
    name: str
    uid: int
    gid: int
    home: str
    shell: str

    @property
    def interactive(self) -> bool:
        return self.shell not in NOLOGIN_SHELLS and bool(self.shell)

    @property
    def human(self) -> bool:
        return 1000 <= self.uid < 60000


def parse_passwd(text: str) -> list[Account]:
    accounts = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[2].isdigit() and parts[3].isdigit():
            accounts.append(Account(parts[0], int(parts[2]), int(parts[3]), parts[5], parts[6]))
    return accounts


def parse_group(text: str) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            groups[parts[0]] = [m for m in parts[3].split(",") if m]
    return groups


def password_state(field: str) -> str:
    if field == "":
        return "EMPTY"
    if field.startswith("!") or field in ("*", "!!"):
        return "locked"
    for prefix, name in HASH_TYPES.items():
        if field.startswith(prefix):
            return name
    return "unknown hash"


def collect_users(ctx: Context) -> list[Note]:
    note = Note("Users & Access", CAT, tags=["users", "access", "sudo"])
    ctx.set_note(note.title)

    accounts = parse_passwd(ctx.read("/etc/passwd", category=CAT, what="Accounts",
                                     required=True) or "")
    groups = parse_group(ctx.read("/etc/group", category=CAT, what="Groups") or "")
    member_of: dict[str, list[str]] = {}
    for group, members in groups.items():
        for m in members:
            member_of.setdefault(m, []).append(group)

    shadow = _shadow(ctx)
    rows = []
    for acc in accounts:
        if not (acc.human or acc.uid == 0 or acc.interactive):
            continue
        rows.append((acc.name, acc.uid, acc.shell, acc.home,
                     ", ".join(sorted(member_of.get(acc.name, []))),
                     shadow.get(acc.name, "needs root")))
    humans = [a for a in accounts if a.human]
    note.summary = f"{len(humans)} user account(s), {len(groups.get('wheel', []))} in wheel"
    note.add(md.heading("Login-capable and human accounts"),
             md.table(("User", "UID", "Shell", "Home", "Groups", "Password"), rows),
             md.callout("example", f"All {len(accounts)} accounts",
                        md.table(("User", "UID", "Shell"),
                                 [(a.name, a.uid, a.shell) for a in accounts]), folded=True))

    _account_checks(ctx, accounts, shadow)
    _group_checks(ctx, note, groups)
    _sudo(ctx, note)
    _homes(ctx, note, humans)
    _logins(ctx, note)
    return [note]


def _shadow(ctx: Context) -> dict[str, str]:
    text = ctx.read("/etc/shadow", category=CAT,
                    what="Password status (empty/locked passwords, hash types)")
    if text is None:
        return {}
    states: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            states[parts[0]] = password_state(parts[1])
    return states


def _account_checks(ctx: Context, accounts: list[Account], shadow: dict[str, str]) -> None:
    extra_root = [a.name for a in accounts if a.uid == 0 and a.name != "root"]
    if extra_root:
        ctx.finding(
            "Additional accounts with UID 0 (root)", Severity.CRITICAL, CAT,
            "These accounts have full root privileges. A second UID-0 account is a classic "
            "backdoor technique.",
            "Investigate immediately; remove or re-number the accounts.",
            evidence=", ".join(extra_root),
        )
    empty = [u for u, s in shadow.items() if s == "EMPTY"]
    if empty:
        ctx.finding(
            "Accounts with an empty password", Severity.CRITICAL, CAT,
            "These accounts can log in without any password.",
            "Set a password (`sudo passwd <user>`) or lock the account (`sudo passwd -l <user>`).",
            evidence=", ".join(empty),
        )
    weak = [u for u, s in shadow.items() if "weak" in s]
    if weak:
        ctx.finding(
            "Passwords stored with weak MD5 hashes", Severity.HIGH, CAT,
            "MD5-crypt hashes can be cracked quickly if `/etc/shadow` leaks.",
            "Have the users change their passwords; Arch defaults to yescrypt.",
            evidence=", ".join(weak),
        )
    sys_shells = [f"{a.name} ({a.shell})" for a in accounts
                  if 0 < a.uid < 1000 and a.interactive and a.name not in ("sync",)]
    if sys_shells:
        ctx.finding(
            "System accounts with an interactive shell", Severity.LOW, CAT,
            "Service accounts normally use `nologin`. A real shell makes a compromised "
            "service easier to turn into an interactive foothold.",
            "`sudo usermod -s /usr/bin/nologin <account>` unless the shell is required.",
            evidence="\n".join(sys_shells),
        )
    if shadow.get("root") not in (None, "locked"):
        ctx.finding(
            "root account has a usable password", Severity.INFO, CAT,
            "Direct root login is possible on the console. Many setups lock root and use "
            "sudo only, which gives per-user accountability.",
            "Optional: `sudo passwd -l root` once sudo works for your user (keep a recovery "
            "plan, e.g. a live USB).",
        )


def _group_checks(ctx: Context, note: Note, groups: dict[str, list[str]]) -> None:
    rows = []
    for group, (sev, meaning) in PRIVILEGED_GROUPS.items():
        members = groups.get(group, [])
        rows.append((group, ", ".join(members) or "—", meaning))
        if members and sev > Severity.INFO:
            ctx.finding(
                f"Users in root-equivalent group '{group}'", sev, CAT,
                f"Members of `{group}` {meaning}.",
                f"Remove users who don't need it: `sudo gpasswd -d <user> {group}`. For "
                "Docker consider rootless mode or podman.",
                evidence=", ".join(members),
            )
    note.add(md.heading("Privileged groups"), md.table(("Group", "Members", "Grants"), rows))


def _sudo(ctx: Context, note: Note) -> None:
    files = ["/etc/sudoers", *(f"/etc/sudoers.d/{n}" for n in ctx.listdir("/etc/sudoers.d"))]
    rules: list[tuple[str, str]] = []
    readable = True
    for path in files:
        text = ctx.read(path)
        if text is None:
            readable = False
            continue
        for line in text.splitlines():
            s = line.strip()
            if (s and not s.startswith("#")) or s.startswith(("#include", "#includedir")):
                rules.append((path, s))
    if not readable:
        ctx.gap("sudo rules (/etc/sudoers)", CAT, GapKind.NEEDS_ROOT,
                "sudoers files are readable only by root")
    if not rules:
        return
    note.add(md.heading("sudo rules"), md.table(("File", "Rule"), rules))
    nopasswd = [f"{p}: {r}" for p, r in rules if "NOPASSWD" in r and not r.startswith("Defaults")]
    if nopasswd:
        ctx.finding(
            "sudo rules without password (NOPASSWD)", Severity.MEDIUM, CAT,
            "Any process running as these users - including malware from a browser or a "
            "malicious package script - can become root silently.",
            "Remove `NOPASSWD:` (edit with `sudo visudo`) or restrict it to specific, "
            "harmless commands.",
            evidence="\n".join(nopasswd),
        )
    if any(re.search(r"Defaults\s+.*!authenticate", r) for _, r in rules):
        ctx.finding(
            "sudo authentication disabled globally", Severity.HIGH, CAT,
            "`Defaults !authenticate` means sudo never asks for a password.",
            "Remove the directive with `sudo visudo`.",
        )


def _homes(ctx: Context, note: Note, humans: list[Account]) -> None:
    rows, open_homes = [], []
    for acc in humans:
        try:
            mode = stat.S_IMODE(ctx.path(acc.home).stat().st_mode)
        except OSError:
            continue
        perms = stat.filemode(mode | stat.S_IFDIR)
        rows.append((acc.name, acc.home, perms))
        if mode & 0o005:
            open_homes.append(f"{acc.home} {perms}")
    if rows:
        note.add(md.heading("Home directory permissions"),
                 md.table(("User", "Home", "Mode"), rows))
    if open_homes:
        ctx.finding(
            "Home directories readable by other users", Severity.LOW, CAT,
            "Other local accounts and services can list or read these home directories.",
            "`chmod 700 /home/<user>`",
            evidence="\n".join(open_homes),
        )


def _logins(ctx: Context, note: Note) -> None:
    if res := ctx.cmd(["last", "-n", "20", "-w"], category=CAT, what="Recent logins",
                      raw_name="last", ok_codes=(0, 1)):
        note.add(md.heading("Recent logins"), md.code(res.stdout))
    defs = ctx.read("/etc/login.defs") or ""
    policy: dict[str, str] = {}
    for line in defs.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] in ("PASS_MAX_DAYS", "PASS_MIN_DAYS",
                                            "ENCRYPT_METHOD", "UMASK"):
            policy[parts[0]] = parts[1].strip()
    faillock = ctx.read("/etc/security/faillock.conf") or ""
    deny = next((ln.split("=", 1)[1].strip() for ln in faillock.splitlines()
                 if ln.strip().startswith("deny") and "=" in ln), "3 (default)")
    note.add(md.heading("Password & lockout policy"),
             md.kv_table([*policy.items(), ("faillock deny after", deny)]))
