"""Write an audit as an Obsidian vault.

Layout (vault root = ``~/Documents/ArchAudit``)::

    ArchAudit/
    ├── Audit History.md               every run, newest first
    ├── About ArchAudit.md             how to read the vault
    └── 2026-10-07 1442 myhost/
        ├── 00 Dashboard.md            start here
        ├── 01 Findings.md             all findings by severity
        ├── 02 Not Collected.md        what could not be gathered + how to fix
        ├── 03 Command Log.md          every command run, status, duration
        ├── System/                    one note per area (Kernel, Network, ...)
        ├── Findings/                  one note per finding (C01, H01, M01, ...)
        ├── Raw/                       raw command output
        └── findings.json              machine-readable, used for "new since last scan"

All links are vault-relative paths, so several runs never collide. Files are
created with O_EXCL|O_NOFOLLOW and 0600 permissions.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from archaudit import __version__, md
from archaudit.core import Finding, Gap, GapKind, Note, RawOutput, Severity, legacy_key

logger = logging.getLogger(__name__)

DASHBOARD = "00 Dashboard"
FINDINGS = "01 Findings"
GAPS = "02 Not Collected"
COMMANDS = "03 Command Log"
FILE_MODE = 0o600
DIR_MODE = 0o700


@dataclass(slots=True)
class AuditResult:
    notes: list[Note]
    findings: list[Finding]
    gaps: list[Gap]
    raw: list[RawOutput]
    facts: dict[str, str]
    started: datetime
    finished: datetime
    is_root: bool
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def hostname(self) -> str:
        return self.facts.get("hostname", "host")

    def counts(self) -> dict[Severity, int]:
        c = Counter(f.severity for f in self.findings)
        return {s: c.get(s, 0) for s in sorted(Severity, reverse=True)}


def _write(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")


def _replace(path: Path, text: str) -> None:
    """Rewrite a vault-level file (history) safely: write new, then rename."""
    tmp = path.with_name(f".{path.name}.tmp")
    if tmp.exists() or tmp.is_symlink():
        tmp.unlink()
    _write(tmp, text)
    os.replace(tmp, path)


def assign_ids(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(findings, key=lambda f: (-f.severity, f.category, f.title))
    counters: Counter[str] = Counter()
    for f in ordered:
        counters[f.severity.prefix] += 1
        f.finding_id = f"{f.severity.prefix}{counters[f.severity.prefix]:02d}"
    return ordered


class VaultWriter:
    def __init__(self, vault: Path) -> None:
        self.vault = vault

    # -- paths -------------------------------------------------------------
    def _run_dir(self, result: AuditResult) -> Path:
        base = f"{result.started:%Y-%m-%d %H%M} {md.safe_filename(result.hostname, 40)}"
        candidate, n = self.vault / base, 1
        while candidate.exists():
            n += 1
            candidate = self.vault / f"{base} ({n})"
        return candidate

    def write(self, result: AuditResult) -> Path:
        self.vault.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
        if self.vault.is_symlink():
            raise OSError(f"refusing to write into symlinked vault {self.vault}")
        previous = self._previous_run(result.hostname)
        run = self._run_dir(result)
        run.mkdir(mode=DIR_MODE)
        for sub in ("System", "Findings", "Raw"):
            (run / sub).mkdir(mode=DIR_MODE)
        self.run_name = run.name
        findings = assign_ids(result.findings)
        note_paths = {n.title: f"{run.name}/{n.folder}/{md.safe_filename(n.title)}"
                      for n in result.notes}
        finding_paths = {f.finding_id: f"{run.name}/Findings/"
                                       f"{f.finding_id} {md.safe_filename(f.title, 70)}"
                         for f in findings}
        self._note_paths, self._finding_paths = note_paths, finding_paths

        raw_paths = self._write_raw(run, result.raw)
        for note in result.notes:
            self._write_system_note(run, note, result)
        for f in findings:
            self._write_finding(run, f, result)
        diff = self._diff(previous, findings)
        _write(run / f"{DASHBOARD}.md", self._dashboard(result, findings, diff))
        _write(run / f"{FINDINGS}.md", self._findings_index(result, findings))
        _write(run / f"{GAPS}.md", self._gaps(result))
        _write(run / f"{COMMANDS}.md", self._command_log(result, raw_paths))
        _write(run / "findings.json", json.dumps(self._json(result, findings), indent=2))
        self._update_history()
        self._about()
        logger.info("vault written", extra={"path": str(run)})
        return run

    def _link(self, rel: str, alias: str | None = None) -> str:
        return md.wikilink(f"{self.run_name}/{rel}", alias)

    def _resolve(self, text: str) -> str:
        return text.replace("[[@/", f"[[{self.run_name}/")

    # -- notes -------------------------------------------------------------
    def _header(self, result: AuditResult, title: str, kind: str, tags: list[str],
                extra: dict[str, object] | None = None) -> str:
        fm: dict[str, object] = {
            "title": title, "type": kind, "host": result.hostname,
            "scan": self.run_name, "date": f"{result.started:%Y-%m-%d %H:%M}",
            **(extra or {}),
            "tags": ["archaudit", f"archaudit/{kind}", *(md.tag(t) for t in tags)],
        }
        nav = (f"{self._link(DASHBOARD, '🏠 Dashboard')} · {self._link(FINDINGS, '🛡 Findings')}"
               f" · {self._link(GAPS, '❓ Not collected')}")
        return f"{md.frontmatter(fm)}\n\n# {title}\n\n{nav}\n"

    def _write_system_note(self, run: Path, note: Note, result: AuditResult) -> None:
        own = [f for f in result.findings if f.source_note == note.title]
        gaps = [g for g in result.gaps if g.category == note.category]
        parts = [self._header(result, note.title, "system", [note.category, *note.tags],
                              {"category": note.category, "findings": len(own)})]
        if note.summary:
            parts.append(f"_{note.summary}_")
        if own:
            items = "\n".join(
                f"- {f.severity.icon} **{f.severity.label}** · "
                f"{md.wikilink(self._finding_paths[f.finding_id], f'{f.finding_id} {f.title}')}"
                for f in sorted(own, key=lambda x: -x.severity))
            worst = max(f.severity for f in own)
            parts.append(md.callout(worst.callout, f"{len(own)} finding(s) in this area", items))
        else:
            parts.append(md.callout("success", "No findings in this area"))
        if gaps:
            parts.append(md.callout("failure", f"{len(gaps)} item(s) not collected for "
                                    f"{note.category}",
                                    "\n".join(f"- **{g.item}** — {g.kind.value}"
                                              + (f": {g.fix}" if g.fix else "") for g in gaps),
                                    folded=True))
        parts += [self._resolve(b) for b in note.body]
        _write(run / note.folder / f"{md.safe_filename(note.title)}.md", "\n\n".join(parts))

    def _write_finding(self, run: Path, f: Finding, result: AuditResult) -> None:
        title = f"{f.finding_id} · {f.title}"
        parts = [self._header(result, title, "finding",
                              [f"severity/{f.severity.name}", f"category/{f.category}"],
                              {"id": f.finding_id, "severity": f.severity.name.lower(),
                               "severity_rank": int(f.severity), "category": f.category,
                               "status": "open"}),
                 md.callout(f.severity.callout, f"{f.severity.icon} {f.severity.label} — "
                            f"{f.category}", f.description)]
        if f.evidence:
            parts += [md.heading("Evidence"), md.code(f.evidence)]
        parts += [md.heading("How to fix"), f.remediation]
        if f.references:
            parts += [md.heading("References"), md.bullet(f"<{r}>" for r in f.references)]
        if f.source_note in self._note_paths:
            parts.append(f"Found by: {md.wikilink(self._note_paths[f.source_note], f.source_note)}")
        name = Path(self._finding_paths[f.finding_id]).name
        _write(run / "Findings" / f"{name}.md", "\n\n".join(parts))

    def _write_raw(self, run: Path, raw: list[RawOutput]) -> dict[str, str]:
        paths: dict[str, str] = {}
        used: set[str] = set()
        for r in raw:
            name = md.safe_filename(r.name)
            while name in used:
                name += "_"
            used.add(name)
            paths[r.command] = f"{self.run_name}/Raw/{name}"
            meta = md.frontmatter({"command": r.command, "status": r.status,
                                   "tags": ["archaudit/raw"]})
            body = (f"{meta}"
                    f"\n\n# {r.name}\n\n`{r.command}` · {r.status} · {r.duration}s\n\n"
                    f"{md.code(r.text)}")
            _write(run / "Raw" / f"{name}.md", body)
        return paths

    # -- index pages -------------------------------------------------------
    def _dashboard(self, result: AuditResult, findings: list[Finding],
                   diff: tuple[list[Finding], list[dict[str, Any]]] | None) -> str:
        counts = result.counts()
        crit, high = counts[Severity.CRITICAL], counts[Severity.HIGH]
        extra: dict[str, object] = {s.name.lower(): n for s, n in counts.items()}
        extra |= {"not_collected": len(result.gaps), "ran_as_root": result.is_root}
        parts = [self._header(result, f"Security audit — {result.hostname}", "dashboard",
                              ["dashboard"], extra)]

        if crit or high:
            parts.append(md.callout("danger", f"{crit + high} critical/high finding(s) need "
                                    "attention", "Start with the top of the table below."))
        elif counts[Severity.MEDIUM]:
            parts.append(md.callout("warning", "No critical issues — some medium findings",
                                    "Review the medium items when you can."))
        else:
            parts.append(md.callout("success", "No significant issues found",
                                    "Only low/informational items remain."))
        if not result.is_root:
            parts.append(md.callout("tip", "Partial audit (not run as root)",
                                    f"Some checks were skipped. Run `sudo archaudit` for full "
                                    f"coverage — see {self._link(GAPS, 'Not Collected')}."))

        f = result.facts
        duration = (result.finished - result.started).total_seconds()
        parts += [
            md.heading("At a glance"),
            md.table(("", "Severity", "Count"),
                     [(s.icon, s.label, n) for s, n in counts.items()]),
            md.kv_table([
                ("Distribution", f.get("distro")), ("Kernel", f.get("kernel", "unknown")),
                ("Last full upgrade", f.get("last_upgrade", "unknown")),
                ("Pending updates", f.get("pending_updates", "not checked")),
                ("Vulnerable packages", f.get("vulnerable_packages", "not checked")),
                ("Network-exposed ports", f.get("exposed_ports", "unknown")),
                ("Root filesystem encrypted", f.get("root_encrypted", "unknown")),
                ("Items not collected", f"{len(result.gaps)} → {self._link(GAPS, 'details')}"),
                ("Ran as root", "yes" if result.is_root else "no"),
                ("Options", ", ".join(k for k, v in result.options.items() if v) or "defaults"),
                ("Duration", f"{duration:.0f}s"),
                ("archaudit version", __version__),
            ]),
        ]
        if diff is not None:
            new, resolved = diff
            parts += [md.heading("Changes since previous scan"),
                      md.kv_table([("New findings", len(new)),
                                   ("Resolved findings", len(resolved))])]
            if new:
                parts.append(md.bullet(
                    f"{x.severity.icon} {md.wikilink(self._finding_paths[x.finding_id], x.title)}"
                    for x in new))
            if resolved:
                parts.append(md.callout("success", "Resolved since last scan",
                                        md.bullet(f"~~{r['title']}~~" for r in resolved)))
        parts += [md.heading("Findings"), self._findings_table(findings)]
        parts += [md.heading("System notes"), md.table(
            ("Note", "Summary", "Findings"),
            [(md.wikilink(self._note_paths[n.title], n.title), n.summary,
              sum(1 for x in findings if x.source_note == n.title)) for n in result.notes])]
        parts += [md.heading("Dataview (optional)"),
                  "With the Dataview community plugin, this live table lists open findings:",
                  md.code(f'TABLE severity, category, status\nFROM "{self.run_name}/Findings"\n'
                          "SORT severity_rank DESC", "dataview")]
        return "\n\n".join(parts)

    def _findings_table(self, findings: list[Finding]) -> str:
        return md.table(("ID", "Severity", "Finding", "Area"), [
            (f.finding_id, f"{f.severity.icon} {f.severity.label}",
             md.wikilink(self._finding_paths[f.finding_id], f.title), f.category)
            for f in findings]) if findings else md.callout("success", "No findings")

    def _findings_index(self, result: AuditResult, findings: list[Finding]) -> str:
        parts = [self._header(result, "Findings", "index", ["findings"])]
        by_sev: dict[Severity, list[Finding]] = defaultdict(list)
        for f in findings:
            by_sev[f.severity].append(f)
        for sev in sorted(Severity, reverse=True):
            items = by_sev.get(sev, [])
            parts.append(md.heading(f"{sev.icon} {sev.label} ({len(items)})"))
            parts.append(self._findings_table(items) if items else "_None._")
        by_cat = Counter(f.category for f in findings)
        parts += [md.heading("By area"), md.table(("Area", "Findings"), by_cat.most_common())]
        return "\n\n".join(parts)

    def _gaps(self, result: AuditResult) -> str:
        parts = [self._header(result, "Not Collected", "gaps", ["gaps"],
                              {"count": len(result.gaps)})]
        if not result.gaps:
            parts.append(md.callout("success", "Everything was collected"))
            return "\n\n".join(parts)
        parts.append("Everything the audit tried to gather but could not, why, and how to "
                     "get it next time. Missing data is **not** the same as a passing check.")
        tools = sorted({g.fix.split("-S ", 1)[1].rstrip("`") for g in result.gaps
                        if g.kind is GapKind.MISSING_TOOL and "pacman -S" in g.fix})
        tips = []
        if any(g.kind is GapKind.NEEDS_ROOT for g in result.gaps):
            tips.append("Run the audit with `sudo` to cover root-only items.")
        if tools:
            tips.append(f"Install missing tools: `sudo pacman -S {' '.join(tools)}`")
        if any(g.kind is GapKind.OFFLINE for g in result.gaps):
            tips.append("Run without `--offline` to check CVEs and pending updates.")
        if tips:
            parts.append(md.callout("tip", "Get full coverage", md.bullet(tips)))
        by_kind: dict[GapKind, list[Gap]] = defaultdict(list)
        for g in result.gaps:
            by_kind[g.kind].append(g)
        for kind, gaps in sorted(by_kind.items(), key=lambda kv: kv[0].value):
            parts += [md.heading(f"{kind.value.capitalize()} ({len(gaps)})"),
                      md.table(("Item", "Area", "Detail", "How to fix"),
                               [(g.item, g.category, g.detail, g.fix) for g in gaps])]
        return "\n\n".join(parts)

    def _command_log(self, result: AuditResult, raw_paths: dict[str, str]) -> str:
        rows = [(md.wikilink(raw_paths[r.command], r.name) if r.command in raw_paths else r.name,
                 f"`{r.command}`", r.status, f"{r.duration}s") for r in result.raw]
        return "\n\n".join([self._header(result, "Command Log", "index", ["raw"]),
                            "Raw output of the main commands, for reference and diffing.",
                            md.table(("Output", "Command", "Status", "Time"), rows)])

    # -- history & diff ----------------------------------------------------
    def _runs(self) -> list[tuple[Path, dict[str, Any]]]:
        runs = []
        for child in self.vault.iterdir():
            data_file = child / "findings.json"
            if child.is_dir() and not child.is_symlink() and data_file.is_file():
                try:
                    runs.append((child, json.loads(data_file.read_text(encoding="utf-8"))))
                except (OSError, json.JSONDecodeError):
                    continue
        return sorted(runs, key=lambda r: str(r[1].get("started", "")), reverse=True)

    def _previous_run(self, host: str) -> dict[str, Any] | None:
        """Newest earlier scan of the *same* host (a vault may hold several)."""
        runs = [data for _, data in self._runs() if data.get("host") == host]
        return runs[0] if runs else None

    def _diff(self, previous: dict[str, Any] | None, findings: list[Finding]
              ) -> tuple[list[Finding], list[dict[str, Any]]] | None:
        """New and resolved findings. Matches on the stable key; scans written
        by 1.0.0 stored title-based keys, so those are compared with digits
        normalised ("7 service socket(s)" == "9 service socket(s)")."""
        if previous is None:
            return None
        old = previous.get("findings", [])
        old_keys = {f.get("key", "") for f in old}
        old_legacy = {legacy_key(f.get("category", ""), f.get("title", "")) for f in old}
        new_keys = {f.key for f in findings}
        new_legacy = {f.legacy_key for f in findings}
        new = [f for f in findings if f.key not in old_keys and f.legacy_key not in old_legacy]
        resolved = [f for f in old if f.get("key") not in new_keys
                    and legacy_key(f.get("category", ""), f.get("title", "")) not in new_legacy]
        return new, resolved

    def _json(self, result: AuditResult, findings: list[Finding]) -> dict[str, Any]:
        return {
            "tool": "archaudit", "version": __version__, "host": result.hostname,
            "started": result.started.isoformat(timespec="seconds"),
            "finished": result.finished.isoformat(timespec="seconds"),
            "ran_as_root": result.is_root, "options": result.options,
            "summary": {s.name.lower(): n for s, n in result.counts().items()}
                       | {"not_collected": len(result.gaps)},
            "facts": result.facts,
            "findings": [{"id": f.finding_id, "key": f.key, "title": f.title,
                          "severity": f.severity.name.lower(), "category": f.category,
                          "evidence": f.evidence} for f in findings],
            "not_collected": [{"item": g.item, "category": g.category, "kind": g.kind.value,
                               "detail": g.detail, "fix": g.fix} for g in result.gaps],
        }

    def _update_history(self) -> None:
        rows = []
        for path, data in self._runs():
            s = data.get("summary", {})
            rows.append((md.wikilink(f"{path.name}/{DASHBOARD}", path.name),
                         s.get("critical", 0), s.get("high", 0), s.get("medium", 0),
                         s.get("low", 0), s.get("info", 0), s.get("not_collected", 0),
                         "yes" if data.get("ran_as_root") else "no"))
        text = "\n\n".join([
            md.frontmatter({"title": "Audit History", "tags": ["archaudit", "archaudit/history"]}),
            "# Audit History",
            "Every archaudit run in this vault, newest first.",
            md.table(("Scan", "🟥 Crit", "🟧 High", "🟨 Med", "🟦 Low", "⬜ Info",
                      "Not collected", "Root"), rows),
        ])
        _replace(self.vault / "Audit History.md", text)

    def _about(self) -> None:
        path = self.vault / "About ArchAudit.md"
        if path.exists() or path.is_symlink():
            return
        _write(path, "\n\n".join([
            md.frontmatter({"title": "About ArchAudit", "tags": ["archaudit"]}),
            "# About ArchAudit",
            "Open this folder as an Obsidian vault. Each scan gets its own folder; start at "
            "its **00 Dashboard** or at [[Audit History]].",
            md.table(("Note", "What it is"), [
                ("00 Dashboard", "Status, key facts, all findings, changes since last scan"),
                ("01 Findings", "Findings grouped by severity"),
                ("02 Not Collected", "What could not be gathered and how to fix that"),
                ("03 Command Log", "Every command run, with links to raw output"),
                ("System/", "Detailed inventory per area"),
                ("Findings/", "One note per finding with evidence and fix"),
            ]),
            md.table(("Severity", "Meaning"), [
                ("🟥 Critical", "Likely exploitable now; fix immediately"),
                ("🟧 High", "Serious weakness; fix soon"),
                ("🟨 Medium", "Hardening gap with real risk"),
                ("🟦 Low", "Best-practice deviation"),
                ("⬜ Info", "Worth knowing; no action required"),
            ]),
            md.callout("warning", "Sensitive data",
                       "These notes map your system's weaknesses. Keep the vault private and "
                       "don't sync it to shared or public locations."),
        ]))
