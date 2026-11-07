"""Debian / Ubuntu package checks (dpkg + apt), read-only.

* ``apt-get -s dist-upgrade`` simulates an upgrade against the package lists
  already on disk, so it needs neither root nor the network, and changes
  nothing. Pending security updates are the ones coming from a ``-security``
  suite.
* ``debsecan`` (Debian only, optional) maps installed versions to CVEs.
* ``/var/log/apt/history.log`` gives the last upgrade; ``apt.conf.d`` shows
  whether unattended upgrades are enabled.
"""

from __future__ import annotations

import re
from datetime import datetime

from archaudit import md
from archaudit.collectors._pkg import add_extra_formats, parse_verify
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Packages"
_INST = re.compile(r"^Inst (?P<pkg>\S+)(?: \[(?P<old>[^\]]+)\])? \((?P<new>\S+) (?P<src>[^\[)]+)")
_START = re.compile(r"^Start-Date: (?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2})")
_UNATTENDED = re.compile(r'APT::Periodic::Unattended-Upgrade\s+"?(?P<v>\d+)"?')


def parse_simulated_upgrade(text: str) -> list[tuple[str, str, str, str]]:
    """``apt-get -s`` output -> [(package, installed, available, source)]."""
    rows = []
    for line in text.splitlines():
        if m := _INST.match(line):
            rows.append((m["pkg"], m["old"] or "", m["new"], m["src"].strip()))
    return rows


def is_security_source(source: str) -> bool:
    # "Debian-Security:12/stable-security", "Ubuntu:24.04/noble-security", "kali-rolling"...
    return any(part.endswith("-security") or part == "Debian-Security"
               for part in re.split(r"[\s/:,]+", source))


def last_apt_upgrade(log_text: str) -> datetime | None:
    """Start time of the newest history.log entry that upgraded packages."""
    last, current = None, None
    for line in log_text.splitlines():
        if m := _START.match(line):
            current = datetime.strptime(f"{m['date']} {m['time']}", "%Y-%m-%d %H:%M")
        elif line.startswith("Upgrade:") and current is not None:
            last = current
    return last


def parse_sources(files: dict[str, str]) -> list[tuple[str, str, list[str]]]:
    """Active apt sources -> [(file, uri, options)] for one-line and deb822 files."""
    out: list[tuple[str, str, list[str]]] = []
    for path, text in files.items():
        if path.endswith(".sources"):
            for stanza in re.split(r"\n\s*\n", text):
                fields: dict[str, str] = {}
                for line in stanza.splitlines():
                    if ":" in line and not line.lstrip().startswith("#"):
                        k, _, v = line.partition(":")
                        fields[k.strip().lower()] = v.strip()
                if fields.get("enabled", "yes").lower() == "no" or "uris" not in fields:
                    continue
                opts = [f"{k}={v}" for k, v in fields.items()
                        if k in ("trusted", "allow-insecure", "allow-weak")]
                out += [(path, uri, opts) for uri in fields["uris"].split()]
        else:
            for raw in text.splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line.startswith(("deb ", "deb-src ")):
                    continue
                options: list[str] = []
                if m := re.search(r"\[([^\]]*)\]", line):
                    options = m[1].split()
                    line = line.replace(m[0], "")
                parts = line.split()
                if len(parts) >= 2:
                    out.append((path, parts[1], options))
    return out


def collect_apt(ctx: Context) -> list[Note]:
    note = Note("Packages", CAT, tags=["packages", "apt", "dpkg"])
    ctx.set_note(note.title)

    inv = ctx.cmd(["dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Package} ${Version}\\n"],
                  category=CAT, what="Installed packages", raw_name="dpkg-query")
    installed = [ln.split(None, 2)[1:] for ln in (inv.lines if inv else [])
                 if ln.startswith("ii") and len(ln.split()) >= 3]
    manual = ctx.cmd(["apt-mark", "showmanual"], category=CAT,
                     what="Manually installed packages")
    manual_lines = manual.lines if manual else []

    note.add(md.heading("Summary"), md.kv_table([
        ("Installed packages", len(installed)),
        ("Manually installed", len(manual_lines)),
    ]))
    pending = _pending(ctx, note)
    _last_upgrade(ctx, note)
    _unattended(ctx, note)
    _sources(ctx, note)
    _orphans(ctx, note)
    _integrity(ctx, note)
    _debsecan(ctx, note)
    add_extra_formats(ctx, note, CAT)
    if manual_lines:
        note.add(md.heading("Manually installed packages"),
                 md.callout("example", f"{len(manual_lines)} packages",
                            md.bullet(manual_lines), folded=True))
    note.summary = (f"{len(installed)} installed, "
                    f"{'unknown' if pending is None else pending} update(s) pending")
    return [note]


def _pending(ctx: Context, note: Note) -> int | None:
    res = ctx.cmd(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"],
                  category=CAT, what="Pending updates", raw_name="apt-get -s dist-upgrade",
                  timeout=180)
    if res is None:
        return None
    rows = parse_simulated_upgrade(res.stdout)
    security = [r for r in rows if is_security_source(r[3])]
    ctx.facts["pending_updates"] = str(len(rows))
    ctx.facts["vulnerable_packages"] = f"{len(security)} security update(s) pending"

    age = _lists_age_days(ctx)
    stale = age is not None and age > 7
    note.add(md.heading("Pending updates"),
             md.kv_table([("Pending", len(rows)), ("From a security suite", len(security)),
                          ("Package lists last refreshed",
                           f"{age} day(s) ago" if age is not None else "unknown")]),
             md.table(("Package", "Installed", "Available", "Source"), rows) if rows else
             md.callout("success", "Up to date", "No pending updates in the current lists."))
    if stale:
        ctx.finding(
            f"Package lists are {age} days old", Severity.LOW, CAT,
            "Pending-update and security results are based on the package lists from the "
            "last `apt update`, so recent security fixes are not visible.",
            "`sudo apt update`, then re-run the audit.", key="stale-lists",
        )
    if security:
        ctx.finding(
            f"{len(security)} security update(s) pending", Severity.HIGH, CAT,
            "Updates from the distribution's security suite are available but not "
            "installed. These fix known vulnerabilities.",
            "`sudo apt update && sudo apt full-upgrade`, then reboot if the kernel or core "
            "libraries were updated.",
            evidence="\n".join(f"{p} {o} -> {n}" for p, o, n, _ in security[:60]),
            key="security-updates",
        )
    other = len(rows) - len(security)
    if other:
        ctx.finding(
            f"{other} other package update(s) pending", Severity.LOW, CAT,
            "Non-security updates are available.", "`sudo apt full-upgrade`",
            evidence="\n".join(f"{p} {o} -> {n}" for p, o, n, s in rows
                               if not is_security_source(s))[:4000],
            key="pending-updates",
        )
    return len(rows)


def _lists_age_days(ctx: Context) -> int | None:
    newest = 0.0
    lists = "/var/lib/apt/lists"
    for name in ctx.listdir(lists):
        if name.endswith(("Release", "InRelease")):
            try:
                newest = max(newest, ctx.path(f"{lists}/{name}").stat().st_mtime)
            except OSError:
                continue
    if not newest:
        return None
    return (datetime.now() - datetime.fromtimestamp(newest)).days


def _last_upgrade(ctx: Context, note: Note) -> None:
    log = ctx.read("/var/log/apt/history.log", category=CAT, what="Last upgrade",
                   max_bytes=32 * 1024 * 1024)
    if log is None:
        return
    when = last_apt_upgrade(log)
    if when is None:  # history.log rotates monthly; an empty current file is normal
        ctx.facts["last_upgrade"] = "not in the current apt history log"
        return
    age = (datetime.now() - when).days
    ctx.facts["last_upgrade"] = f"{when:%Y-%m-%d} ({age} days ago)"
    note.add(md.kv_table([("Last upgrade (apt history)", ctx.facts["last_upgrade"])]))
    if age > 30:
        ctx.finding(
            f"No package upgrades for {age} days", Severity.MEDIUM, CAT,
            "No package has been upgraded in over a month, so published security fixes "
            "are probably missing.",
            "`sudo apt update && sudo apt full-upgrade`, and consider enabling "
            "unattended-upgrades.",
            evidence=f"last upgrade in /var/log/apt/history.log: {when:%Y-%m-%d %H:%M}",
            key="stale-upgrade",
        )


def _unattended(ctx: Context, note: Note) -> None:
    enabled = None
    for name in ctx.listdir("/etc/apt/apt.conf.d"):
        for m in _UNATTENDED.finditer(ctx.read(f"/etc/apt/apt.conf.d/{name}") or ""):
            enabled = m["v"] != "0"  # later files override earlier ones
    installed = ctx.exists("/usr/bin/unattended-upgrade")
    state = ("enabled" if enabled and installed else
             "installed but disabled" if installed else "not installed")
    note.add(md.kv_table([("Automatic security updates (unattended-upgrades)", state)]))
    if state != "enabled":
        ctx.finding(
            "Automatic security updates are not enabled", Severity.LOW, CAT,
            "Without unattended-upgrades, security fixes are only installed when someone "
            "remembers to upgrade.",
            "`sudo apt install unattended-upgrades && "
            "sudo dpkg-reconfigure -plow unattended-upgrades`",
            evidence=f"unattended-upgrades: {state}",
            references=["https://wiki.debian.org/UnattendedUpgrades"],
            key="auto-updates",
        )


def _sources(ctx: Context, note: Note) -> None:
    files = {}
    for path in ["/etc/apt/sources.list",
                 *(f"/etc/apt/sources.list.d/{n}" for n in ctx.listdir("/etc/apt/sources.list.d")
                   if n.endswith((".list", ".sources")))]:
        if (text := ctx.read(path)) is not None:
            files[path] = text
    sources = parse_sources(files)
    note.add(md.heading("Package sources"),
             md.table(("File", "URI", "Options"),
                      [(f, u, " ".join(o)) for f, u, o in sources]))
    trusted = [f"{f}: {u} [{' '.join(o)}]" for f, u, o in sources
               if any(x.lower() in ("trusted=yes", "allow-insecure=yes", "allow-weak=yes")
                      for x in o)]
    if trusted:
        ctx.finding(
            "Package sources with signature checking disabled", Severity.HIGH, CAT,
            "`trusted=yes` / `allow-insecure=yes` makes apt accept unsigned or badly signed "
            "packages from these sources, so a malicious mirror or MITM can supply packages.",
            "Remove the option and install the repository's signing key with `signed-by=`.",
            evidence="\n".join(trusted), key="weak-signatures",
        )
    third_party = sorted({u for _, u, _ in sources
                          if not re.search(r"(debian|ubuntu|kali|raspbian|linuxmint)\.(org|"
                                           r"com|net)", u)})
    if third_party:
        note.add(md.callout("info", "Third-party repositories",
                            "Packages from these are not covered by the distribution's "
                            "security team:\n" + md.bullet(third_party)))


def _orphans(ctx: Context, note: Note) -> None:
    res = ctx.cmd(["apt-get", "-s", "-o", "Debug::NoLocking=1", "autoremove"], category=CAT,
                  what="Unneeded packages")
    if res is None:
        return
    orphans = [ln.split()[1] for ln in res.lines if ln.startswith("Remv ")]
    if orphans:
        note.add(md.heading("Unneeded packages"), md.bullet(orphans))
        ctx.finding(
            f"{len(orphans)} unneeded package(s) installed", Severity.INFO, CAT,
            "Automatically installed dependencies that nothing needs anymore still need "
            "updates and enlarge the attack surface.",
            "Review, then `sudo apt autoremove`.", evidence="\n".join(orphans), key="orphans",
        )


def _integrity(ctx: Context, note: Note) -> None:
    what = "Package file integrity (dpkg --verify)"
    if not ctx.deep:
        ctx.gap(what, CAT, GapKind.SKIPPED, "checksums every installed file (slow)",
                "Re-run with `--deep`")
        return
    res = ctx.cmd(["dpkg", "--verify"], category=CAT, what=what, raw_name="dpkg --verify",
                  ok_codes=(0, 1), timeout=max(ctx.timeout, 900))
    if res is None:
        return
    missing, modified = parse_verify(res.stdout)
    note.add(md.heading("Package file integrity"),
             md.kv_table([("Missing files", len(missing)),
                          ("Modified files (outside /etc)", len(modified))]))
    if missing:
        ctx.finding(
            f"{len(missing)} file(s) from installed packages are missing", Severity.LOW, CAT,
            "Files owned by packages have been deleted. Often harmless (cleaned docs) but can "
            "indicate tampering or a broken install.",
            "Reinstall affected packages: `sudo apt install --reinstall <pkg>` "
            "(`dpkg -S <file>` shows the package).",
            evidence="\n".join(missing[:40]), key="missing-files",
        )
    if modified:
        ctx.finding(
            f"{len(modified)} package file(s) modified outside /etc", Severity.MEDIUM, CAT,
            "Binaries or libraries differ from what the package shipped: tampering, disk "
            "corruption, or a manual edit.",
            "Investigate each file, then `sudo apt install --reinstall <pkg>`.",
            evidence="\n".join(modified[:40]), key="modified-files",
        )


def _debsecan(ctx: Context, note: Note) -> None:
    what = "CVE matching (debsecan)"
    if ctx.platform.distro_id != "debian":
        ctx.gap(what, CAT, GapKind.NOT_PRESENT,
                f"no offline CVE matcher for {ctx.platform.name}; pending security-suite "
                "updates are reported instead")
        return
    if ctx.offline:
        ctx.gap(what, CAT, GapKind.OFFLINE, "debsecan downloads tracker data",
                "Run without `--offline`")
        return
    codename = _codename(ctx)
    argv = ["debsecan", "--format", "detail", "--only-fixed"]
    if codename:
        argv[1:1] = ["--suite", codename]
    res = ctx.cmd(argv, category=CAT, what=what, raw_name="debsecan", timeout=180)
    if res is None:
        return
    cves = [ln.split()[0] for ln in res.lines if ln.startswith("CVE-")]
    note.add(md.heading("CVEs with a fix available (debsecan)"),
             md.kv_table([("CVEs", len(set(cves)))]),
             md.callout("example", "debsecan output", md.code(res.stdout), folded=True))


def _codename(ctx: Context) -> str:
    for line in (ctx.read("/etc/os-release") or "").splitlines():
        if line.startswith("VERSION_CODENAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return ""
