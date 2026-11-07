"""Package-manager helpers shared by collectors (pacman, dpkg/apt, rpm/dnf).

Other collectors ask "which package owns this file?" or "is this package
installed?" through these functions instead of calling pacman directly.
"""

from __future__ import annotations

from collections.abc import Iterable

from archaudit import md
from archaudit.core import Context, Note


def manager(ctx: Context) -> str:
    """The package manager actually present: pacman, dpkg, rpm or ''."""
    family = ctx.platform.family
    preferred = {"arch": "pacman", "debian": "dpkg", "fedora": "rpm"}.get(family)
    if preferred and ctx.has(preferred):
        return preferred
    for tool in ("pacman", "dpkg", "rpm"):  # unknown distro: use whatever exists
        if ctx.has(tool):
            return tool
    return ""


def installed_versions(ctx: Context, names: Iterable[str]) -> dict[str, str]:
    """{package: version} for the installed packages among ``names``."""
    names = list(names)
    if not names:
        return {}
    match manager(ctx):
        case "pacman":
            argv = ["pacman", "-Q", *names]
        case "dpkg":
            argv = ["dpkg-query", "-W", "-f=${Package} ${db:Status-Abbrev} ${Version}\\n",
                    *names]
        case "rpm":
            argv = ["rpm", "-q", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\\n", *names]
        case _:
            return {}
    res = ctx.runner.run(argv, ctx.timeout, ok_codes=range(256))
    versions: dict[str, str] = {}
    for line in res.stdout.splitlines():
        parts = line.split()
        if argv[0] == "dpkg-query":
            # "name ii  1.2-3": only "ii" (installed) counts
            if len(parts) == 3 and parts[1].startswith("ii"):
                versions[parts[0]] = parts[2]
        elif len(parts) == 2 and parts[0] in names:
            versions[parts[0]] = parts[1]
    return versions


NOT_OWNED = "not owned by any package"


def owners(ctx: Context, paths: list[str]) -> dict[str, str]:
    """Map files to their owning package ('not owned by any package' if none)."""
    if not paths or str(ctx.root) != "/":
        return {}
    match manager(ctx):
        case "pacman":
            return _pacman_owners(ctx, paths)
        case "dpkg":
            return {p: _dpkg_owner(ctx, p) for p in paths}
        case "rpm":
            return {p: _rpm_owner(ctx, p) for p in paths}
    return {}


def _pacman_owners(ctx: Context, paths: list[str]) -> dict[str, str]:
    res = ctx.runner.run(["pacman", "-Qo", *paths], ctx.timeout, ok_codes=(0, 1))
    found: dict[str, str] = {}
    for line in (res.stdout + "\n" + res.stderr).splitlines():
        if " is owned by " in line:
            path, _, pkg = line.partition(" is owned by ")
            found[path.strip()] = pkg.strip()
        elif line.startswith("error: No package owns "):
            found[line.removeprefix("error: No package owns ").strip()] = NOT_OWNED
    return found


def _dpkg_owner(ctx: Context, path: str) -> str:
    # dpkg records some files under their pre-/usr-merge path (/bin/x for /usr/bin/x).
    candidates = [path] + ([path.removeprefix("/usr")] if path.startswith("/usr/") else [])
    for candidate in candidates:
        res = ctx.runner.run(["dpkg-query", "-S", candidate], ctx.timeout, ok_codes=(0, 1))
        for line in res.stdout.splitlines():
            pkgs, sep, owned = line.rpartition(": ")
            if sep and owned.strip() == candidate:
                return pkgs.strip()
    return NOT_OWNED


def _rpm_owner(ctx: Context, path: str) -> str:
    res = ctx.runner.run(["rpm", "-qf", "--qf", "%{NAME}\\n", path], ctx.timeout,
                         ok_codes=(0, 1))
    lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
    if res.returncode == 0 and lines and "not owned" not in lines[0]:
        return ", ".join(lines)
    return NOT_OWNED


def parse_verify(text: str) -> tuple[list[str], list[str]]:
    """Parse ``dpkg --verify`` / ``rpm -Va`` output.

    Both print ``<flags> [attr] <path>`` where a ``5`` in the flags means the
    checksum changed and attr ``c`` marks a config file; missing files are
    reported as ``missing ... <path>``. Returns (missing, modified) where
    modified excludes config files and anything under /etc.
    """
    missing, modified = [], []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "missing":
            missing.append(parts[-1])
            continue
        if len(parts) < 2 or len(parts[0]) < 8:
            continue
        flags, path = parts[0], parts[-1]
        attr = parts[1] if len(parts) == 3 else ""
        if "5" in flags and attr != "c" and not path.startswith("/etc/"):
            modified.append(path)
    return missing, modified


def add_extra_formats(ctx: Context, note: Note, category: str) -> None:
    """Flatpak and Snap inventory, the same on every distribution."""
    for extra, argv in (("Flatpak apps", ["flatpak", "list", "--app",
                                         "--columns=application,version"]),
                        ("Snap packages", ["snap", "list"])):
        if res := ctx.cmd(argv, category=category, what=extra, quiet_missing=True):
            note.add(md.heading(extra), md.code(res.stdout))
