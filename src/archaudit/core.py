"""Core models: severities, findings, gaps, notes, command runner and context.

Every collector receives a :class:`Context`. All file reads and command
executions go through it, so that

* anything that fails (missing tool, permission denied, timeout) is recorded
  as a :class:`Gap` with a concrete fix, instead of silently disappearing;
* raw command output is kept for the "Raw" section of the vault;
* tests can point the context at a fake filesystem root and a fake runner.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Protocol

from archaudit.platforms import Platform, detect, is_admin

logger = logging.getLogger(__name__)

MAX_RAW_BYTES = 256 * 1024  # cap stored raw output per command

_DENIED_MARKERS = (
    "permission denied", "operation not permitted", "must be root", "access denied",
    "you need to be root", "are not allowed", "insufficient privileges",
    "access is denied", "requires elevation", "unauthorizedaccess",
    "must be an administrator", "administrator privilege",
)


_NO_SYSTEMD = ("Failed to connect to bus", "System has not been booted with systemd",
               "No journal files were found")


class Severity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @property
    def callout(self) -> str:
        """Obsidian callout type used to render this severity."""
        return {5: "danger", 4: "danger", 3: "warning", 2: "note", 1: "info"}[self.value]

    @property
    def icon(self) -> str:
        return {5: "🟥", 4: "🟧", 3: "🟨", 2: "🟦", 1: "⬜"}[self.value]

    @property
    def prefix(self) -> str:
        return self.name[0]


class GapKind(StrEnum):
    NEEDS_ROOT = "needs root"
    MISSING_TOOL = "tool not installed"
    NOT_PRESENT = "not present on this system"
    OFFLINE = "skipped (offline mode)"
    SKIPPED = "skipped (option)"
    TIMEOUT = "timed out"
    ERROR = "error"


@dataclass(slots=True)
class Finding:
    """A security-relevant observation with a remediation."""

    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    evidence: str = ""
    references: list[str] = field(default_factory=list)
    source_note: str = ""          # title of the note that produced it
    finding_id: str = ""           # assigned by the writer
    ident: str = ""                # stable identity; defaults to the title

    @property
    def key(self) -> str:
        """Stable identity used to compare findings across scans.

        Titles often contain counts ("7 service socket(s) ..."), so findings
        whose title varies pass an explicit ``ident`` and keep the same key
        from scan to scan.
        """
        return f"{self.category}::{self.ident or self.title}"

    @property
    def legacy_key(self) -> str:
        """Key with digits normalised, to match scans written by 1.0.0."""
        return legacy_key(self.category, self.title)


def legacy_key(category: str, title: str) -> str:
    return f"{category}::{re.sub(r'[0-9]+', '#', title)}"


@dataclass(slots=True)
class Gap:
    """Something the audit wanted but could not collect."""

    item: str
    category: str
    kind: GapKind
    detail: str = ""
    fix: str = ""
    package: str = ""  # package that would provide a missing tool


@dataclass(slots=True)
class Note:
    """One Markdown note in the vault (System/<title>.md)."""

    title: str
    category: str
    folder: str = "System"
    tags: list[str] = field(default_factory=list)
    body: list[str] = field(default_factory=list)
    summary: str = ""  # one line shown on the dashboard

    def add(self, *blocks: str) -> None:
        self.body.extend(b for b in blocks if b)


class CmdStatus(StrEnum):
    OK = "ok"
    MISSING = "missing"
    DENIED = "denied"
    TIMEOUT = "timeout"
    FAILED = "failed"


@dataclass(slots=True)
class CommandResult:
    argv: tuple[str, ...]
    status: CmdStatus
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status is CmdStatus.OK

    @property
    def lines(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.strip()]


class Runner(Protocol):
    def which(self, name: str) -> str | None: ...

    def run(self, argv: Sequence[str], timeout: float,
            ok_codes: Sequence[int]) -> CommandResult: ...


class SubprocessRunner:
    """Runs fixed argv lists - never through a shell - with a fixed PATH and a
    minimal environment, so a hostile PATH or locale cannot change results."""

    LINUX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin"
    # Windows: only system directories, so a planted powershell.exe elsewhere
    # on PATH (e.g. in a user-writable folder) is never picked up.
    # "Sysnative" only exists for 32-bit processes on 64-bit Windows and reaches
    # the 64-bit PowerShell (the 32-bit one lacks e.g. Get-LocalUser).
    WINDOWS_DIRS = ("Sysnative\\WindowsPowerShell\\v1.0", "System32\\WindowsPowerShell\\v1.0",
                    "System32", "System32\\wbem", "")
    WINDOWS_ENV = ("SystemRoot", "windir", "SystemDrive", "ProgramData", "ProgramFiles",
                   "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "COMPUTERNAME",
                   "USERNAME", "USERDOMAIN", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP",
                   "TMP", "PATHEXT", "ComSpec", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
                   "OS")

    def __init__(self, windows: bool | None = None) -> None:
        self.windows = os.name == "nt" if windows is None else windows
        if self.windows:
            root = os.environ.get("SystemRoot", r"C:\Windows")  # noqa: SIM112 - Windows casing
            self.search_path = ";".join(
                f"{root}\\{d}" if d else root for d in self.WINDOWS_DIRS)
            self._env = {k: os.environ[k] for k in self.WINDOWS_ENV if k in os.environ}
            self._env |= {"PATH": self.search_path, "NO_COLOR": "1"}
        else:
            self.search_path = self.LINUX_PATH
            self._env = {
                "PATH": self.search_path,
                "LC_ALL": "C",
                "LANG": "C",
                "SYSTEMD_COLORS": "0",
                "SYSTEMD_PAGER": "",
                "NO_COLOR": "1",
                "HOME": os.environ.get("HOME", "/root"),
            }

    def which(self, name: str) -> str | None:
        return shutil.which(name, path=self.search_path)

    def run(self, argv: Sequence[str], timeout: float,
            ok_codes: Sequence[int]) -> CommandResult:
        args = tuple(argv)
        exe = self.which(args[0])
        if exe is None:
            return CommandResult(args, CmdStatus.MISSING)
        started = time.monotonic()
        # Windows: no console window flashing up for each command.
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if self.windows else 0
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [exe, *args[1:]], capture_output=True, timeout=timeout,
                env=self._env, stdin=subprocess.DEVNULL, check=False, creationflags=flags,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(args, CmdStatus.TIMEOUT, duration=timeout)
        except OSError as exc:
            return CommandResult(args, CmdStatus.FAILED, stderr=str(exc))
        duration = round(time.monotonic() - started, 3)
        out = proc.stdout.decode("utf-8", errors="replace").removeprefix("\ufeff")
        err = proc.stderr.decode("utf-8", errors="replace").removeprefix("\ufeff")
        if proc.returncode in ok_codes:
            status = CmdStatus.OK
        elif any(m in err.lower() for m in _DENIED_MARKERS):
            status = CmdStatus.DENIED
        else:
            status = CmdStatus.FAILED
        return CommandResult(args, status, proc.returncode, out, err, duration)


@dataclass(slots=True)
class RawOutput:
    name: str
    category: str
    command: str
    status: str
    duration: float
    text: str


class Context:
    """Shared state and safe I/O helpers for collectors."""

    def __init__(
        self,
        *,
        root: Path = Path("/"),
        runner: Runner | None = None,
        is_root: bool | None = None,
        offline: bool = False,
        deep: bool = False,
        timeout: float = 60.0,
        platform: Platform | None = None,
    ) -> None:
        self.platform = platform or detect(root)
        if self.platform.is_windows and root == Path("/"):
            # file reads (e.g. /ProgramData/ssh/sshd_config) are relative to C:\
            root = Path(os.environ.get("SystemDrive", "C:") + "\\")  # noqa: SIM112
        self.root = root
        self.runner: Runner = runner or SubprocessRunner(windows=self.platform.is_windows)
        # "root" means administrator on Windows throughout the code.
        self.is_root = is_admin() if is_root is None else is_root
        self.offline = offline
        self.deep = deep
        self.timeout = timeout
        self.findings: list[Finding] = []
        self.gaps: list[Gap] = []
        self.raw: list[RawOutput] = []
        self.facts: dict[str, str] = {   # key facts shared between collectors/dashboard
            "platform": self.platform.family,
            "elevate_hint": self.platform.elevate_hint,
            "install_cmd": self.platform.install_cmd,
        }
        self._current_note = ""

    # -- bookkeeping -----------------------------------------------------
    def set_note(self, title: str) -> None:
        self._current_note = title

    def finding(self, title: str, severity: Severity, category: str, description: str,
                remediation: str, evidence: str = "",
                references: Sequence[str] = (), key: str = "") -> Finding:
        f = Finding(title, severity, category, description, remediation, evidence,
                    list(references), self._current_note, ident=key)
        self.findings.append(f)
        logger.debug("finding", extra={"title": title, "severity": severity.name})
        return f

    def gap(self, item: str, category: str, kind: GapKind, detail: str = "",
            fix: str = "", package: str = "") -> None:
        if not fix and kind is GapKind.NEEDS_ROOT:
            fix = self.platform.elevate_hint
        self.gaps.append(Gap(item, category, kind, detail, fix, package))
        logger.debug("gap", extra={"item": item, "kind": kind.value})

    # -- files -----------------------------------------------------------
    def path(self, p: str) -> Path:
        return self.root / p.lstrip("/")

    def exists(self, p: str) -> bool:
        return self.path(p).exists()

    def read(self, p: str, *, category: str = "", what: str = "",
             required: bool = False, max_bytes: int = 4 * 1024 * 1024) -> str | None:
        """Read a text file. Records a gap when ``what`` is given and it fails.

        ``required`` marks files whose absence is itself unusual (otherwise a
        missing optional file is silently treated as "not configured").
        """
        target = self.path(p)
        try:
            with target.open("rb") as fh:
                return fh.read(max_bytes).decode("utf-8", errors="replace")
        except PermissionError:
            if what:
                self.gap(what, category, GapKind.NEEDS_ROOT, f"cannot read `{p}`")
        except FileNotFoundError:
            if what and required:
                self.gap(what, category, GapKind.NOT_PRESENT, f"`{p}` does not exist")
        except OSError as exc:
            if what:
                self.gap(what, category, GapKind.ERROR, f"`{p}`: {exc}")
        return None

    def listdir(self, p: str) -> list[str]:
        try:
            return sorted(os.listdir(self.path(p)))
        except OSError:
            return []

    # -- commands --------------------------------------------------------
    def has(self, command: str) -> bool:
        return self.runner.which(command) is not None

    def cmd(
        self,
        argv: Sequence[str],
        *,
        category: str,
        what: str,
        raw_name: str | None = None,
        ok_codes: Sequence[int] = (0,),
        timeout: float | None = None,
        needs_root: bool = False,
        quiet_missing: bool = False,
        label: str | None = None,
    ) -> CommandResult | None:
        """Run a command; on failure record a gap and return ``None``.

        ``needs_root``: skip (with a gap) when not root, instead of producing
        partial or misleading output. ``label``: how the command is shown in
        the report (for long PowerShell scripts).
        """
        command = label or " ".join(argv)
        if needs_root and not self.is_root:
            self.gap(what, category, GapKind.NEEDS_ROOT, f"`{command}` requires "
                     + ("administrator rights" if self.platform.is_windows else "root"))
            return None
        result = self.runner.run(argv, timeout or self.timeout, ok_codes)
        if raw_name and result.status in (CmdStatus.OK, CmdStatus.FAILED):
            text = result.stdout or result.stderr
            if len(text) > MAX_RAW_BYTES:
                text = text[:MAX_RAW_BYTES] + "\n… [truncated]"
            self.raw.append(RawOutput(raw_name, category, command, result.status.value,
                                      result.duration, text))
        match result.status:
            case CmdStatus.OK:
                return result
            case CmdStatus.MISSING:
                if not quiet_missing:
                    fix, pkg = self.platform.install_hint(argv[0])
                    self.gap(what, category, GapKind.MISSING_TOOL,
                             f"`{argv[0]}` not found", fix, pkg)
            case CmdStatus.DENIED:
                self.gap(what, category, GapKind.NEEDS_ROOT, f"`{command}`: permission denied")
            case CmdStatus.TIMEOUT:
                self.gap(what, category, GapKind.TIMEOUT, f"`{command}` exceeded time limit",
                         "Re-run with a larger `--timeout`")
            case CmdStatus.FAILED if any(m in result.stderr for m in _NO_SYSTEMD):
                self.gap(what, category, GapKind.NOT_PRESENT,
                         "systemd is not running (container or chroot)")
            case CmdStatus.FAILED:
                detail = (result.stderr.strip().splitlines() or [f"exit {result.returncode}"])[-1]
                self.gap(what, category, GapKind.ERROR, f"`{command}`: {detail[:200]}")
        return None


Collector = Callable[[Context], list[Note]]
