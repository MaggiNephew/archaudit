"""Command-line entry point.

Exit codes: 0 = no critical/high findings, 1 = critical/high findings present,
2 = the audit could not run or write its report, 130 = interrupted.

When started via ``sudo`` on Linux, the audit *collects* as root but *writes*
the vault as the invoking user (a forked child drops privileges), so the files
belong to that user and root never follows user-controlled paths or symlinks.
On Windows an elevated run writes directly into the user's own profile.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
import time
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from archaudit import __version__
from archaudit.collectors import collectors_for
from archaudit.core import Context, GapKind, Severity
from archaudit.platforms import Platform, detect
from archaudit.writer import AuditResult, VaultWriter

logger = logging.getLogger("archaudit")


class _Formatter(logging.Formatter):
    def __init__(self, as_json: bool) -> None:
        super().__init__()
        self.as_json = as_json
        self._reserved = set(vars(logging.makeLogRecord({}))) | {"message", "taskName"}

    def format(self, record: logging.LogRecord) -> str:
        extras = {k: v for k, v in vars(record).items() if k not in self._reserved}
        if self.as_json:
            return json.dumps({"ts": self.formatTime(record), "level": record.levelname,
                               "msg": record.getMessage(), **extras}, default=str)
        tail = " ".join(f"{k}={v}" for k, v in extras.items())
        return f"{record.levelname:<7} {record.getMessage()}" + (f"  {tail}" if tail else "")


def setup_logging(level: str, as_json: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_Formatter(as_json))
    root = logging.getLogger("archaudit")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = False


def target_user() -> tuple[str, int, int, Path]:
    """The human the report is for: $SUDO_USER under sudo, else the caller."""
    if sys.platform == "win32":
        return getpass.getuser(), -1, -1, Path.home()
    import pwd
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user and sudo_user != "root":
        pw = pwd.getpwnam(sudo_user)
    else:
        pw = pwd.getpwuid(os.getuid())
    return pw.pw_name, pw.pw_uid, pw.pw_gid, Path(pw.pw_dir)


def _windows_documents() -> Path | None:
    """The real Documents folder (it may be redirected, e.g. to OneDrive)."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    try:
        # FOLDERID_Documents {FDD39AD0-238F-46AF-ADB4-6C85480369C7}
        folder = GUID(0xFDD39AD0, 0x238F, 0x46AF,
                      (ctypes.c_ubyte * 8)(0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7))
        out = ctypes.c_wchar_p()
        if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(folder), 0, None,
                                                      ctypes.byref(out)):
            return None
        path = Path(out.value or "")
        ctypes.windll.ole32.CoTaskMemFree(out)
        return path if path.name else None
    except (AttributeError, OSError):
        return None


def documents_dir(home: Path) -> Path:
    """Linux: XDG_DOCUMENTS_DIR from ~/.config/user-dirs.dirs if set.
    Windows: the Documents known folder."""
    if os.name == "nt":
        return _windows_documents() or home / "Documents"
    try:
        for line in (home / ".config" / "user-dirs.dirs").read_text().splitlines():
            if line.startswith("XDG_DOCUMENTS_DIR="):
                value = line.split("=", 1)[1].strip().strip('"').replace("$HOME", str(home))
                if value and value != str(home):
                    return Path(value)
    except OSError:
        pass
    return home / "Documents"


def default_vault(home: Path) -> Path:
    """~/Documents/ArchAudit, unless Documents is synced by OneDrive: the vault
    maps the machine's weaknesses and should not leave it."""
    docs = documents_dir(home)
    if "onedrive" in str(docs).lower():
        logger.warning("Documents is synced by OneDrive; writing the vault to "
                       f"{home / 'ArchAudit'} instead (use -o to choose another folder)")
        return home / "ArchAudit"
    return docs / "ArchAudit"


def build_parser(areas: Sequence[str] = ()) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="archaudit",
        description="Read-only security & inventory audit for Linux (Arch, Debian/Ubuntu, "
                    "Fedora/RHEL) and Windows, written as an Obsidian vault. Run with "
                    "sudo / as administrator for full coverage.")
    p.add_argument("--version", action="version", version=f"archaudit {__version__}")
    p.add_argument("-o", "--output", type=Path,
                   help="vault folder (default: ~/Documents/ArchAudit of the invoking user)")
    p.add_argument("--offline", action="store_true",
                   help="skip checks that need the network (CVE data, update metadata)")
    p.add_argument("--deep", action="store_true",
                   help="slower checks: package checksums, whole-filesystem SUID scan")
    p.add_argument("--only", nargs="+", choices=list(areas) or None, metavar="AREA",
                   help=f"run only these areas: {', '.join(areas)}")
    p.add_argument("--skip", nargs="+", choices=list(areas) or None, metavar="AREA",
                   help="skip these areas")
    p.add_argument("--timeout", type=float, default=60.0,
                   help="per-command timeout in seconds (default 60)")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--log-json", action="store_true", help="JSON log lines on stderr")
    return p


def run_audit(ctx: Context, areas: Sequence[str]) -> AuditResult:
    started = datetime.now().astimezone()
    collectors = collectors_for(ctx.platform)
    notes = []
    for i, name in enumerate(areas, 1):
        logger.info(f"[{i}/{len(areas)}] {name}")
        t0 = time.monotonic()
        try:
            notes += collectors[name](ctx)
        except Exception as exc:  # one broken collector must not sink the audit
            logger.exception("collector failed", extra={"area": name})
            ctx.gap(f"{name} checks", name.capitalize(), GapKind.ERROR,
                    f"collector crashed: {type(exc).__name__}: {exc}",
                    "Please report this with the log output")
        logger.debug("collector done", extra={"area": name,
                                              "seconds": round(time.monotonic() - t0, 2)})
    return AuditResult(notes=notes, findings=ctx.findings, gaps=ctx.gaps, raw=ctx.raw,
                       facts=ctx.facts, started=started, finished=datetime.now().astimezone(),
                       is_root=ctx.is_root,
                       options={"offline": ctx.offline, "deep": ctx.deep})


def write_as_user(result: AuditResult, vault: Path, uid: int, gid: int) -> Path:
    """Write the vault, dropping root privileges first when running under sudo."""
    if sys.platform == "win32" or os.geteuid() != 0 or uid == 0:
        return VaultWriter(vault).write(result)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # child: become the user, write, report path through the pipe
        code = 0
        try:
            os.close(read_fd)
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            os.umask(0o077)
            path = VaultWriter(vault).write(result)
            os.write(write_fd, str(path).encode())
        except BaseException as exc:
            os.write(write_fd, f"ERROR:{exc}".encode())
            code = 1
        finally:
            os._exit(code)
    os.close(write_fd)
    chunks = []
    while chunk := os.read(read_fd, 4096):
        chunks.append(chunk)
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    message = b"".join(chunks).decode(errors="replace")
    if os.waitstatus_to_exitcode(status) != 0 or message.startswith("ERROR:"):
        raise OSError(message.removeprefix("ERROR:") or "writer process failed")
    return Path(message)


def main(argv: Sequence[str] | None = None, platform: Platform | None = None) -> int:
    platform = platform or detect()
    available = list(collectors_for(platform))
    args = build_parser(available).parse_args(argv)
    setup_logging(args.log_level, args.log_json)
    user, uid, gid, home = target_user()
    vault = args.output or default_vault(home)
    areas = [a for a in (args.only or available) if a not in (args.skip or [])]

    ctx = Context(offline=args.offline, deep=args.deep, timeout=args.timeout,
                  platform=platform)
    if not ctx.is_root:
        logger.warning("not running with full privileges: some checks will be listed under "
                       f"'Not Collected' ({platform.elevate_hint.replace('**', '')})")
    try:
        result = run_audit(ctx, areas)
        run_dir = write_as_user(result, vault, uid, gid)
    except KeyboardInterrupt:
        logger.warning("interrupted")
        return 130
    except OSError as exc:
        logger.error(f"could not write report to {vault}: {exc}")
        return 2

    counts = result.counts()
    summary = ", ".join(f"{n} {s.name.lower()}" for s, n in counts.items() if n) or "no findings"
    print(f"\nAudit complete for {result.hostname}: {summary}; "
          f"{len(result.gaps)} item(s) not collected.")
    print(f"Open in Obsidian: {run_dir}/00 Dashboard.md  (vault: {vault}, user: {user})")
    return 1 if counts[Severity.CRITICAL] or counts[Severity.HIGH] else 0


if __name__ == "__main__":
    raise SystemExit(main())
