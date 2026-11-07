"""Fedora / RHEL-family package checks (rpm + dnf), read-only.

* ``dnf check-update`` lists pending updates (``-C`` = cache only in
  ``--offline`` mode, so no metadata download happens).
* ``dnf updateinfo list --security`` lists pending security advisories with
  their severity (works with dnf4 and dnf5).
* ``/etc/yum.repos.d/*.repo`` is checked for disabled GPG checking.
"""

from __future__ import annotations

import re

from archaudit import md
from archaudit.collectors._pkg import add_extra_formats, parse_verify
from archaudit.collectors._util import active
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Packages"
_ADVISORY_SEVERITY = re.compile(r"\b(Critical|Important|Moderate|Low)\b", re.I)
_SEV = {"critical": Severity.CRITICAL, "important": Severity.HIGH,
        "moderate": Severity.MEDIUM, "low": Severity.LOW}
AUTO_UPDATE_TIMERS = ("dnf-automatic.timer", "dnf-automatic-install.timer",
                      "dnf5-automatic.timer", "packagekit-offline-update.service")


def parse_check_update(text: str) -> list[tuple[str, str, str]]:
    """``dnf check-update`` -> [(package, version, repo)]."""
    rows = []
    for line in text.splitlines():
        if line.startswith("Obsoleting"):  # dnf4 lists replaced packages after this
            break
        parts = line.split()
        if len(parts) == 3 and "." in parts[0]:
            rows.append((parts[0], parts[1], parts[2]))
    return rows


def parse_security_advisories(text: str) -> list[tuple[str, Severity, str]]:
    """dnf4: ``FEDORA-2026-1a2b Important/Sec. pkg-1.2.fc41.x86_64``;
    dnf5: ``FEDORA-2026-1a2b security Important pkg-1.2.fc41.x86_64 2026-…``."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or not re.match(r"^[A-Z][A-Z0-9]*-\d{4}", parts[0]):
            continue
        m = _ADVISORY_SEVERITY.search(line)
        sev = _SEV[m[1].lower()] if m else Severity.MEDIUM
        pkg = next((p for p in parts[1:] if re.search(r"\.(x86_64|aarch64|noarch|i686)$", p)),
                   parts[-1])
        out.append((parts[0], sev, pkg))
    return out


def parse_repo_files(files: dict[str, str]) -> list[tuple[str, str, dict[str, str]]]:
    """[(file, [section], options)] for every repo section."""
    out: list[tuple[str, str, dict[str, str]]] = []
    for path, text in files.items():
        section, opts = "", dict[str, str]()
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if line.startswith("[") and line.endswith("]"):
                if section:
                    out.append((path, section, opts))
                section, opts = line[1:-1], {}
            elif "=" in line and section:
                k, _, v = line.partition("=")
                opts[k.strip().lower()] = v.strip()
        if section:
            out.append((path, section, opts))
    return out


def collect_dnf(ctx: Context) -> list[Note]:
    note = Note("Packages", CAT, tags=["packages", "dnf", "rpm"])
    ctx.set_note(note.title)
    dnf = "dnf5" if ctx.has("dnf5") and not ctx.has("dnf") else "dnf"

    inv = ctx.cmd(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\\n"], category=CAT,
                  what="Installed packages", raw_name="rpm -qa")
    total = len(inv.lines) if inv else 0
    note.add(md.heading("Summary"), md.kv_table([("Installed packages", total)]))

    pending = _pending(ctx, note, dnf)
    _security(ctx, note, dnf)
    _repos(ctx, note)
    _auto_updates(ctx, note)
    _integrity(ctx, note)
    add_extra_formats(ctx, note, CAT)
    note.summary = (f"{total} installed, "
                    f"{'unknown' if pending is None else pending} update(s) pending")
    return [note]


def _dnf_argv(ctx: Context, dnf: str, *args: str) -> list[str]:
    return [dnf, "-q", *(["-C"] if ctx.offline else []), *args]


def _pending(ctx: Context, note: Note, dnf: str) -> int | None:
    # exit 100 = updates available, 0 = none
    res = ctx.cmd(_dnf_argv(ctx, dnf, "check-update"), category=CAT, what="Pending updates",
                  raw_name="dnf check-update", ok_codes=(0, 100), timeout=300)
    if res is None:
        return None
    rows = parse_check_update(res.stdout)
    ctx.facts["pending_updates"] = str(len(rows))
    note.add(md.heading("Pending updates"),
             md.table(("Package", "Available", "Repository"), rows) if rows else
             md.callout("success", "Up to date", "No pending updates."))
    if rows:
        ctx.finding(
            f"{len(rows)} package update(s) pending", Severity.LOW, CAT,
            "Updates are available. Security-relevant ones are listed separately.",
            f"`sudo {dnf} upgrade --refresh`",
            evidence="\n".join(f"{p} -> {v}" for p, v, _ in rows[:60]),
            key="pending-updates",
        )
    return len(rows)


def _security(ctx: Context, note: Note, dnf: str) -> None:
    res = ctx.cmd(_dnf_argv(ctx, dnf, "updateinfo", "list", "--security"), category=CAT,
                  what="Pending security advisories", raw_name="dnf updateinfo --security",
                  timeout=300)
    if res is None:
        return
    advisories = parse_security_advisories(res.stdout)
    ctx.facts["vulnerable_packages"] = f"{len({a for a, _, _ in advisories})} advisories pending"
    note.add(md.heading("Pending security advisories"),
             md.table(("Advisory", "Severity", "Package"),
                      [(a, f"{s.icon} {s.label}", p) for a, s, p in advisories])
             if advisories else md.callout("success", "No pending security advisories"))
    if advisories:
        worst = max(s for _, s, _ in advisories)
        ctx.finding(
            f"{len({a for a, _, _ in advisories})} security advisory(ies) pending", worst, CAT,
            "Security updates published by the distribution are not installed.",
            f"`sudo {dnf} upgrade --refresh --security` (or a full upgrade), then reboot if "
            "the kernel or core libraries changed.",
            evidence="\n".join(f"{a} {s.label} {p}" for a, s, p in advisories[:60]),
            key="security-updates",
        )


def _repos(ctx: Context, note: Note) -> None:
    files = {f"/etc/yum.repos.d/{n}": ctx.read(f"/etc/yum.repos.d/{n}") or ""
             for n in ctx.listdir("/etc/yum.repos.d") if n.endswith(".repo")}
    main = parse_repo_files({"/etc/dnf/dnf.conf": ctx.read("/etc/dnf/dnf.conf") or ""})
    global_gpg = next((o.get("gpgcheck") for _, s, o in main if s == "main"), None)
    repos = parse_repo_files(files)
    enabled = [(f, s, o) for f, s, o in repos if o.get("enabled", "1") not in ("0", "false")]
    note.add(md.heading("Repositories"),
             md.table(("File", "Repo", "gpgcheck", "Base URL"),
                      [(f, s, o.get("gpgcheck", global_gpg or "default"),
                        o.get("baseurl") or o.get("metalink") or o.get("mirrorlist", ""))
                       for f, s, o in enabled]))
    weak = [f"{f} [{s}] gpgcheck={o.get('gpgcheck', global_gpg)}" for f, s, o in enabled
            if o.get("gpgcheck", global_gpg or "1") in ("0", "false", "no")]
    if weak:
        ctx.finding(
            "Repositories with package signature checking disabled", Severity.HIGH, CAT,
            "`gpgcheck=0` makes dnf install unsigned packages from these repositories, so a "
            "malicious mirror or MITM can supply packages.",
            "Set `gpgcheck=1` and import the repository's signing key.",
            evidence="\n".join(weak), key="weak-signatures",
        )


def _auto_updates(ctx: Context, note: Note) -> None:
    timers = active(ctx, AUTO_UPDATE_TIMERS)
    note.add(md.kv_table([("Automatic updates", ", ".join(timers) or "none active")]))
    if not timers:
        ctx.finding(
            "Automatic security updates are not enabled", Severity.LOW, CAT,
            "No dnf-automatic timer is active, so security fixes are only installed when "
            "someone upgrades (desktop editions may still offer them through GNOME "
            "Software/KDE Discover).",
            "`sudo dnf install dnf-automatic` and enable `dnf-automatic.timer` "
            "(set `apply_updates = yes` / `upgrade_type = security`).",
            key="auto-updates",
        )


def _integrity(ctx: Context, note: Note) -> None:
    what = "Package file integrity (rpm -Va)"
    if not ctx.deep:
        ctx.gap(what, CAT, GapKind.SKIPPED, "checksums every installed file (slow)",
                "Re-run with `--deep`")
        return
    res = ctx.cmd(["rpm", "-Va"], category=CAT, what=what, raw_name="rpm -Va",
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
            "Files owned by packages have been deleted (often harmless docs/locales).",
            "Reinstall affected packages: `sudo dnf reinstall <pkg>` "
            "(`rpm -qf <file>` shows the package).",
            evidence="\n".join(missing[:40]), key="missing-files",
        )
    if modified:
        ctx.finding(
            f"{len(modified)} package file(s) modified outside /etc", Severity.MEDIUM, CAT,
            "Binaries or libraries differ from what the package shipped.",
            "Investigate each file, then `sudo dnf reinstall <pkg>`.",
            evidence="\n".join(modified[:40]), key="modified-files",
        )
