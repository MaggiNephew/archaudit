"""Package inventory and package-level vulnerability checks.

* ``arch-audit`` maps installed packages to the Arch Security Tracker (CVEs).
* ``checkupdates`` (pacman-contrib) lists pending updates without touching the
  real sync database.
* ``/var/log/pacman.log`` tells us when the last full upgrade happened.
* ``pacman.conf`` and the mirrorlist are checked for weakened signature
  verification and plain-HTTP mirrors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from archaudit import md
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Packages"
TRACKER = "https://security.archlinux.org"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# arch-audit has printed two layouts over the years:
#   old:  Package curl is affected by CVE-1, CVE-2. High risk! Update to 8.4.0-1!
#   new:  pam is affected by arbitrary filesystem access. (CVE-2025-6020). High risk!
# Both may end with "Update to [at least] X[ from testing repos]!".
_ARCH_AUDIT_LINE = re.compile(
    r"^(?:Package )?(?P<pkg>\S+) is affected by (?P<issues>.+?)\.?"
    r"(?:\s*\((?P<cves>[^)]*)\)\.?)?\s+"
    r"(?P<sev>[A-Za-z]+) risk!\.?"
    r"(?:\s+Update to (?:at least )?(?P<fix>\S+?)(?P<testing> from testing repos)?!)?\s*$"
)
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_FULL_UPGRADE = re.compile(
    r"^\[(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2})[^\]]*\] "
    r"\[PACMAN\] starting full system upgrade"
)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "unknown": Severity.LOW,
}


@dataclass(frozen=True, slots=True)
class VulnerablePackage:
    name: str
    issues: str
    cves: tuple[str, ...]
    severity: Severity
    fixed_version: str | None
    fix_in_testing: bool


def parse_arch_audit(text: str) -> tuple[list[VulnerablePackage], list[str]]:
    """Parse arch-audit's text output. Returns (packages, unparsed_lines)."""
    packages, unparsed = [], []
    for raw in text.splitlines():
        line = _ANSI.sub("", raw).strip()
        if not line:
            continue
        m = _ARCH_AUDIT_LINE.match(line)
        if not m:
            unparsed.append(line)
            continue
        issues = m["issues"]
        cves = tuple(dict.fromkeys(_CVE.findall(f"{issues} {m['cves'] or ''}")))
        packages.append(VulnerablePackage(
            name=m["pkg"], issues=issues, cves=cves,
            severity=_SEVERITY_MAP.get(m["sev"].lower(), Severity.MEDIUM),
            fixed_version=m["fix"], fix_in_testing=bool(m["testing"]),
        ))
    return packages, unparsed


def parse_pacman_conf(text: str) -> dict[str, dict[str, list[str]]]:
    """Parse pacman.conf into {section: {key: [values]}} (repeated keys kept)."""
    sections: dict[str, dict[str, list[str]]] = {}
    current = "options"
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        key, _, value = line.partition("=")
        sections.setdefault(current, {}).setdefault(key.strip(), []).append(value.strip())
    return sections


def siglevel_risk(value: str) -> tuple[Severity, str] | None:
    """Rate a SigLevel value. Package-level weakness is what matters most."""
    worst: tuple[Severity, str] | None = None
    for token in value.split():
        scope = "package" if token.startswith("Package") else \
            "database" if token.startswith("Database") else "both"
        base = token.removeprefix("Package").removeprefix("Database")
        sev: Severity | None = None
        if base == "Never":
            sev = Severity.HIGH if scope != "database" else Severity.LOW
        elif base in ("Optional", "TrustAll"):
            sev = Severity.MEDIUM if scope != "database" else None
        if sev and (worst is None or sev > worst[0]):
            worst = (sev, token)
    return worst


def last_full_upgrade(log_text: str) -> datetime | None:
    last = None
    for line in log_text.splitlines():
        if m := _FULL_UPGRADE.match(line):
            last = m
    if last is None:
        return None
    return datetime.strptime(f"{last['date']} {last['time']}", "%Y-%m-%d %H:%M")


def collect_packages(ctx: Context) -> list[Note]:
    note = Note("Packages", CAT, tags=["packages", "pacman"])
    vuln_note = Note("Vulnerable Packages", CAT, tags=["packages", "vulnerabilities", "cve"])
    ctx.set_note(note.title)

    if not ctx.has("pacman"):
        ctx.gap("Package inventory", CAT, GapKind.NOT_PRESENT,
                "`pacman` not found - not an Arch-based system")
        note.summary = "pacman not available"
        note.add(md.callout("failure", "pacman not found",
                            "Package checks were skipped."))
        return [note]

    all_pkgs = ctx.cmd(["pacman", "-Q"], category=CAT, what="Installed packages",
                       raw_name="pacman -Q")
    explicit = ctx.cmd(["pacman", "-Qe"], category=CAT, what="Explicitly installed packages")
    foreign = ctx.cmd(["pacman", "-Qm"], category=CAT, what="Foreign (AUR) packages",
                      ok_codes=(0, 1))
    orphans = ctx.cmd(["pacman", "-Qdtq"], category=CAT, what="Orphaned packages",
                      ok_codes=(0, 1))

    total = len(all_pkgs.lines) if all_pkgs else 0
    explicit_lines = explicit.lines if explicit else []
    foreign_lines = foreign.lines if foreign else []
    orphan_lines = orphans.lines if orphans else []
    helpers = [h for h in ("yay", "paru", "pikaur", "trizen", "aura") if ctx.has(h)]

    note.add(
        md.heading("Summary"),
        md.kv_table([
            ("Installed packages", total),
            ("Explicitly installed", len(explicit_lines)),
            ("Foreign / AUR packages", len(foreign_lines)),
            ("Orphans (unneeded dependencies)", len(orphan_lines)),
            ("AUR helpers present", ", ".join(helpers) or "none"),
        ]),
        md.callout("info", "Related",
                   f"See {md.wikilink('@/System/Vulnerable Packages', 'Vulnerable Packages')} "
                  "for CVEs."),
    )

    _last_upgrade(ctx, note)
    _pending_updates(ctx, note)
    _pacman_config(ctx, note)
    _integrity(ctx, note)

    if foreign_lines:
        note.add(md.heading("Foreign / AUR packages"),
                 md.table(("Package", "Version"), [ln.split(maxsplit=1) for ln in foreign_lines]))
        ctx.finding(
            f"{len(foreign_lines)} AUR/foreign package(s) are outside security tracking",
            Severity.INFO, CAT,
            "Packages not from the official repositories are not covered by the Arch "
            "Security Tracker or `arch-audit`, and are not signed by Arch developers. "
            "You must track their updates and review their PKGBUILDs yourself.",
            "Update them regularly with your AUR helper; remove ones you no longer use.",
            evidence="\n".join(foreign_lines[:50]),
            key="foreign-packages",
        )
    if orphan_lines:
        note.add(md.heading("Orphaned packages"), md.bullet(orphan_lines))
        ctx.finding(
            f"{len(orphan_lines)} orphaned package(s) installed", Severity.INFO, CAT,
            "Orphans are dependencies nothing needs anymore. They still enlarge the attack "
            "surface and need updates.",
            "Review, then `sudo pacman -Rns $(pacman -Qdtq)`.",
            evidence="\n".join(orphan_lines),
            key="orphans",
        )
    if explicit_lines:
        rows = [ln.split(maxsplit=1) for ln in explicit_lines]
        note.add(md.heading("Explicitly installed packages"),
                 md.callout("example", f"{len(rows)} packages",
                            md.table(("Package", "Version"), rows), folded=True))

    for extra, argv in (("Flatpak apps", ["flatpak", "list", "--app",
                                         "--columns=application,version"]),
                        ("Snap packages", ["snap", "list"])):
        if res := ctx.cmd(argv, category=CAT, what=extra, quiet_missing=True):
            note.add(md.heading(extra), md.code(res.stdout))

    ctx.set_note(vuln_note.title)
    _vulnerabilities(ctx, vuln_note)
    note.summary = f"{total} installed, {len(foreign_lines)} AUR, {len(orphan_lines)} orphans"
    return [note, vuln_note]


def _vulnerabilities(ctx: Context, note: Note) -> None:
    note.add(md.callout("abstract", "Source",
                        f"Installed package versions matched against the "
                        f"[Arch Security Tracker]({TRACKER}) by `arch-audit`."))
    if ctx.offline:
        ctx.gap("Vulnerable packages (CVEs)", CAT, GapKind.OFFLINE,
                "arch-audit needs to download tracker data", "Run without `--offline`")
        note.summary = "skipped (offline)"
        return
    # Prefer CVE IDs in the output; older arch-audit builds lack --show-cve.
    what = "Vulnerable packages (CVEs)"
    res = ctx.cmd(["arch-audit", "--show-cve"], category=CAT, what=what,
                  raw_name="arch-audit", ok_codes=(0, 1), timeout=120)
    if res is None and ctx.has("arch-audit"):
        ctx.gaps = [g for g in ctx.gaps if g.item != what]  # retry replaces the gap
        res = ctx.cmd(["arch-audit"], category=CAT, what=what,
                      raw_name="arch-audit", ok_codes=(0, 1), timeout=120)
    if res is None:
        note.summary = "not checked"
        note.add(md.callout("failure", "Not checked",
                            "Install `arch-audit` to enable CVE matching:\n"
                            "`sudo pacman -S arch-audit`"))
        return

    vulns, unparsed = parse_arch_audit(res.stdout)
    vulns.sort(key=lambda v: (-v.severity, v.name))
    fixable = [v for v in vulns if v.fixed_version]
    unfixed = [v for v in vulns if not v.fixed_version]

    if unparsed and not vulns:
        # Output we cannot read must never look like "nothing vulnerable".
        ctx.facts["vulnerable_packages"] = f"unknown ({len(unparsed)} unparsed lines)"
        note.summary = "arch-audit output could not be parsed"
        note.add(md.callout("failure", "arch-audit output not understood",
                            "None of the lines matched a known format, so vulnerable "
                            "packages could not be counted. The raw output is below."),
                 md.code("\n".join(unparsed)))
        ctx.gap("Vulnerable packages (CVEs)", CAT, GapKind.ERROR,
                f"arch-audit printed {len(unparsed)} line(s) in an unknown format",
                "Please report this together with the Raw/arch-audit note")
        return

    note.summary = f"{len(fixable)} with a fix available, {len(unfixed)} without a fix yet"
    ctx.facts["vulnerable_packages"] = (f"{len(fixable)} fixable, {len(unfixed)} unfixed"
                                        if vulns else "0")

    if not vulns and not unparsed:
        note.add(md.callout("success", "No known vulnerable packages",
                            "Every installed repo package is clear in the tracker."))
        return

    def rows(items: list[VulnerablePackage]) -> list[tuple[str, str, str, str]]:
        return [(f"{v.severity.icon} {v.severity.label}", v.name,
                 (v.fixed_version or "no fix yet") + (" (testing)" if v.fix_in_testing else ""),
                 ", ".join(v.cves) or v.issues) for v in items]

    if fixable:
        note.add(md.heading("Fix available — update now"),
                 md.table(("Risk", "Package", "Fixed in", "Issues"), rows(fixable)))
    if unfixed:
        note.add(md.heading("No fixed version yet"),
                 md.callout("abstract", "About this list",
                            "The tracker has open issues for these packages but no fixed "
                            "release. Many are long-lived entries (old CVEs that are disputed, "
                            "only affect unusual configurations, or wait for upstream). "
                            "Updating will not help; check the tracker for workarounds."),
                 md.table(("Risk", "Package", "Fixed in", "Issues"), rows(unfixed)))
    if unparsed:
        note.add(md.heading("Unparsed arch-audit output"), md.code("\n".join(unparsed)))
        ctx.gap("Some arch-audit lines", CAT, GapKind.ERROR,
                f"{len(unparsed)} line(s) in an unexpected format; shown raw in the note")

    for v in fixable:
        fix = (f"Update now: `sudo pacman -Syu` (fixed in **{v.fixed_version}**"
               + (", currently only in the testing repos)." if v.fix_in_testing else ")."))
        ctx.finding(
            f"Vulnerable package: {v.name}", v.severity, CAT,
            f"`{v.name}` has known security issues with a fixed release available: "
            f"{v.issues}.",
            fix,
            evidence=", ".join(v.cves) or v.issues,
            references=[f"{TRACKER}/package/{v.name}",
                        *(f"{TRACKER}/{c}" for c in v.cves[:10])],
        )
    if unfixed:
        serious = [v for v in unfixed if v.severity >= Severity.HIGH]
        ctx.finding(
            f"{len(unfixed)} package(s) with open security issues and no fix yet",
            Severity.MEDIUM if serious else Severity.LOW, CAT,
            "The Arch Security Tracker lists open issues for these packages but no fixed "
            "version exists, so updating cannot resolve them. They are grouped here "
            "instead of one finding each because many are old, disputed or "
            "configuration-dependent entries."
            + (f" {len(serious)} are rated high or critical by the tracker; review those "
               "first." if serious else ""),
            "Review the high/critical entries on the tracker, limit exposure of the affected "
            "software where possible (e.g. don't open untrusted files with it), and remove "
            "packages you don't need. Re-run the audit after updates.",
            evidence="\n".join(f"{v.severity.label}: {v.name} ({', '.join(v.cves) or v.issues})"
                               for v in unfixed),
            references=[TRACKER],
            key="unfixed-vulnerabilities",
        )


def _last_upgrade(ctx: Context, note: Note) -> None:
    log = ctx.read("/var/log/pacman.log", category=CAT, what="Last full system upgrade",
                   max_bytes=64 * 1024 * 1024)
    if log is None:
        return
    when = last_full_upgrade(log)
    if when is None:
        ctx.gap("Last full system upgrade", CAT, GapKind.NOT_PRESENT,
                "no `pacman -Syu` found in pacman.log")
        return
    age = (datetime.now() - when).days
    ctx.facts["last_upgrade"] = f"{when:%Y-%m-%d} ({age} days ago)"
    note.add(md.heading("Updates"),
             md.kv_table([("Last full upgrade (pacman -Syu)", ctx.facts["last_upgrade"])]))
    if age > 14:
        ctx.finding(
            f"System not fully upgraded for {age} days",
            Severity.MEDIUM if age > 30 else Severity.LOW, CAT,
            "Arch is a rolling release: security fixes arrive only through full upgrades. "
            "Partial upgrades are unsupported.",
            "Run `sudo pacman -Syu` (and update AUR packages) at least weekly.",
            evidence=f"last 'starting full system upgrade': {when:%Y-%m-%d %H:%M}",
            references=["https://wiki.archlinux.org/title/System_maintenance"],
            key="stale-upgrade",
        )


def _pending_updates(ctx: Context, note: Note) -> None:
    if ctx.offline:
        ctx.gap("Pending updates", CAT, GapKind.OFFLINE, "checkupdates needs the network",
                "Run without `--offline`")
        return
    # checkupdates: exit 0 = updates listed, 2 = no updates, 1 = error.
    res = ctx.cmd(["checkupdates"], category=CAT, what="Pending updates",
                  raw_name="checkupdates", ok_codes=(0, 2), timeout=180)
    if res is None:
        return
    pending = res.lines
    note.add(md.heading("Pending updates"),
             md.table(("Package", "Installed", "Available"),
                      [(p[0], p[1], p[3]) for ln in pending
                       if len(p := ln.split()) >= 4]) if pending else
             md.callout("success", "Up to date", "No pending repository updates."))
    ctx.facts["pending_updates"] = str(len(pending))
    if pending:
        kernel = any(ln.split()[0].startswith("linux") for ln in pending)
        ctx.finding(
            f"{len(pending)} package update(s) pending", Severity.LOW, CAT,
            "Updates are available in the repositories. Security-relevant ones are "
            "listed separately under Vulnerable Packages."
            + (" A kernel update is included (reboot afterwards)." if kernel else ""),
            "`sudo pacman -Syu`",
            evidence="\n".join(pending[:60]),
            key="pending-updates",
        )


def _pacman_config(ctx: Context, note: Note) -> None:
    text = ctx.read("/etc/pacman.conf", category=CAT, what="pacman.conf", required=True)
    if text is None:
        return
    conf = parse_pacman_conf(text)
    repos = [s for s in conf if s != "options"]
    rows = []
    for section, values in conf.items():
        for level in values.get("SigLevel", []):
            rows.append((section, level))
            if risk := siglevel_risk(level):
                sev, token = risk
                ctx.finding(
                    f"Weak package signature checking ({section}: {token})", sev, CAT,
                    "pacman will install packages whose signatures are missing or not "
                    "verified, allowing a malicious mirror or MITM to supply packages.",
                    "Use the default `SigLevel = Required DatabaseOptional` in "
                    "`/etc/pacman.conf` and fix keyring problems with "
                    "`sudo pacman -S archlinux-keyring` instead.",
                    evidence=f"[{section}] SigLevel = {level}",
                    references=["https://wiki.archlinux.org/title/Pacman/Package_signing"],
                )
    ignored = [v for k in ("IgnorePkg", "IgnoreGroup")
               for v in conf.get("options", {}).get(k, []) if v]
    testing = [r for r in repos if "testing" in r]
    note.add(md.heading("pacman configuration"),
             md.kv_table([("Enabled repositories", ", ".join(repos)),
                          ("Testing repos", ", ".join(testing) or "none"),
                          ("IgnorePkg / IgnoreGroup", " ".join(ignored) or "none")]),
             md.table(("Section", "SigLevel"), rows) if rows else "")
    if ignored:
        ctx.finding(
            "Packages are excluded from upgrades", Severity.LOW, CAT,
            "IgnorePkg/IgnoreGroup hold packages back, so they miss security fixes and can "
            "cause partial-upgrade breakage.",
            "Remove the entries from `/etc/pacman.conf` once the reason is resolved.",
            evidence=" ".join(ignored),
        )

    mirrors = ctx.read("/etc/pacman.d/mirrorlist") or ""
    active = [ln.split("=", 1)[1].strip() for ln in mirrors.splitlines()
              if ln.strip().startswith("Server") and "=" in ln]
    plain = [m for m in active if m.startswith("http://")]
    note.add(md.kv_table([("Active mirrors", len(active)),
                          ("Plain-HTTP mirrors", len(plain))]))
    if plain:
        ctx.finding(
            f"{len(plain)} mirror(s) use plain HTTP", Severity.LOW, CAT,
            "Packages are signature-checked, but HTTP lets an attacker on the network see "
            "what you install and attempt stale-metadata (freeze) attacks.",
            "Use HTTPS mirrors only, e.g. `reflector --protocol https ...`.",
            evidence="\n".join(plain[:10]),
            key="http-mirrors",
        )


def _integrity(ctx: Context, note: Note) -> None:
    if ctx.deep:
        argv, what = ["pacman", "-Qkk"], "Package file integrity (checksums)"
        if not ctx.is_root:
            ctx.gap(what, CAT, GapKind.NEEDS_ROOT,
                    "files in root-only directories cannot be verified; ran -Qk instead")
            argv, what = ["pacman", "-Qk"], "Package file integrity (existence)"
    else:
        argv, what = ["pacman", "-Qk"], "Package file integrity (existence)"
    res = ctx.runner.run(argv, max(ctx.timeout, 600), ok_codes=(0, 1))
    if res.status.value in ("timeout", "missing"):
        ctx.gap(what, CAT, GapKind.TIMEOUT if res.status.value == "timeout"
                else GapKind.MISSING_TOOL)
        return
    text = res.stdout + "\n" + res.stderr
    missing = [ln for ln in text.splitlines() if "(No such file or directory)" in ln]
    modified = [ln for ln in text.splitlines()
                if "mismatch" in ln and "/etc/" not in ln and "Modification time" not in ln]
    note.add(md.heading("Package file integrity"),
             md.kv_table([("Check", " ".join(argv)),
                          ("Missing files", len(missing)),
                          ("Modified files (outside /etc)", len(modified) if ctx.deep
                           else "not checked (use --deep)")]))
    if missing:
        ctx.finding(
            f"{len(missing)} file(s) from installed packages are missing", Severity.LOW, CAT,
            "Files owned by packages have been deleted. Often harmless (cleaned docs/locales) "
            "but can indicate tampering or a broken install.",
            "Reinstall affected packages: `sudo pacman -S <pkg>`.",
            evidence="\n".join(missing[:40]),
            key="missing-files",
        )
    if modified:
        ctx.finding(
            f"{len(modified)} package file(s) modified outside /etc", Severity.MEDIUM, CAT,
            "Binaries or libraries differ from what the package shipped. This can be "
            "tampering, disk corruption, or a manual edit.",
            "Investigate each file, then reinstall the owning package "
            "(`pacman -Qo <file>`, `sudo pacman -S <pkg>`).",
            evidence="\n".join(modified[:40]),
            key="modified-files",
        )
