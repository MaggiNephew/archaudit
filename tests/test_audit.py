"""End-to-end: simulated Arch system -> collectors -> Obsidian vault."""

import json
import os
import re
import stat
from pathlib import Path

import pytest
from conftest import FakeRunner

from archaudit.cli import documents_dir, run_audit
from archaudit.collectors import COLLECTORS
from archaudit.core import Context, GapKind, Severity
from archaudit.writer import VaultWriter

LINK = re.compile(r"\[\[([^\]|\\]+)")


def _audit(root: Path, runner: FakeRunner, is_root: bool = True, **kw: bool):
    ctx = Context(root=root, runner=runner, is_root=is_root, **kw)
    return run_audit(ctx, list(COLLECTORS))


def _titles(result) -> dict[str, Severity]:
    return {f.title: f.severity for f in result.findings}


def test_detects_expected_issues(fake_root: Path, runner: FakeRunner) -> None:
    result = _audit(fake_root, runner)
    t = _titles(result)
    assert t["Vulnerable package: openssl"] is Severity.CRITICAL
    assert t["Vulnerable package: curl"] is Severity.HIGH
    assert t["Additional accounts with UID 0 (root)"] is Severity.CRITICAL
    assert t["Accounts with an empty password"] is Severity.CRITICAL
    assert t["Passwords stored with weak MD5 hashes"] is Severity.HIGH
    assert t["Weak package signature checking (myrepo: Never)"] is Severity.HIGH
    assert t["CPU mitigations disabled on the kernel command line"] is Severity.HIGH
    assert t["CPU vulnerable to 1 side-channel issue(s)"] is Severity.HIGH
    assert t["Kernel upgraded but system not rebooted"] is Severity.MEDIUM
    assert t["CPU microcode package intel-ucode not installed"] is Severity.MEDIUM
    assert t["SSH permits direct root login"] is Severity.HIGH
    assert t["Redis (often unauthenticated) listening on all interfaces (port 6379)"] \
        is Severity.HIGH
    assert t["sudo rules without password (NOPASSWD)"] is Severity.MEDIUM
    assert t["Users in root-equivalent group 'docker'"] is Severity.MEDIUM
    assert "SSH brute-force activity: 25 failed logins in 30 days" in t
    assert t["System not fully upgraded for 45 days"] is Severity.MEDIUM
    assert "1 mirror(s) use plain HTTP" in t
    assert "Packages are excluded from upgrades" in t
    assert "2 package update(s) pending" in t
    assert "Home directories readable by other users" in t
    # SSH password auth is "no" (Match block must not leak into global settings)
    assert "SSH accepts password logins" in t  # KbdInteractive defaults to yes
    assert result.facts["vulnerable_packages"] == "3"


def test_secrets_never_reach_the_report(fake_root: Path, runner: FakeRunner,
                                        tmp_path: Path) -> None:
    result = _audit(fake_root, runner)
    run = VaultWriter(tmp_path / "vault").write(result)
    blob = "\n".join(p.read_text() for p in run.rglob("*") if p.is_file())
    assert "$y$j9T$salt$hash" not in blob and "$1$abc$def" not in blob


def test_non_root_records_gaps_instead_of_guessing(fake_root: Path, runner: FakeRunner) -> None:
    (fake_root / "etc" / "shadow").chmod(0)
    result = _audit(fake_root, runner, is_root=False)
    kinds = {(g.item, g.kind) for g in result.gaps}
    assert ("Firewall rules (nftables ruleset)", GapKind.NEEDS_ROOT) in kinds
    assert ("Effective sshd configuration", GapKind.NEEDS_ROOT) in kinds
    if os.geteuid() != 0:  # root ignores file modes
        assert any(i.startswith("Password status") and k is GapKind.NEEDS_ROOT
                   for i, k in kinds)


def test_missing_tools_and_offline_are_reported(fake_root: Path, runner: FakeRunner) -> None:
    runner.installed.discard("arch-audit")
    result = _audit(fake_root, runner)
    gap = next(g for g in result.gaps if g.item == "Vulnerable packages (CVEs)")
    assert gap.kind is GapKind.MISSING_TOOL and "pacman -S arch-audit" in gap.fix

    offline = _audit(fake_root, FakeRunner(runner.responses, runner.installed), offline=True)
    assert {g.kind for g in offline.gaps if g.category == "Packages"} >= {GapKind.OFFLINE}


def test_collector_crash_becomes_gap(fake_root: Path, runner: FakeRunner,
                                     monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(ctx):  # type: ignore[no-untyped-def]
        raise RuntimeError("kaboom")
    monkeypatch.setitem(COLLECTORS, "logs", boom)
    result = _audit(fake_root, runner)
    assert any("kaboom" in g.detail for g in result.gaps)


def test_vault_structure_links_and_permissions(fake_root: Path, runner: FakeRunner,
                                               tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    run = VaultWriter(vault).write(_audit(fake_root, runner))
    for name in ("00 Dashboard.md", "01 Findings.md", "02 Not Collected.md",
                 "03 Command Log.md", "findings.json"):
        assert (run / name).is_file()
    assert (vault / "Audit History.md").is_file() and (vault / "About ArchAudit.md").is_file()
    assert any((run / "Findings").glob("C01 *.md"))
    assert stat.S_IMODE(run.stat().st_mode) == 0o700
    assert stat.S_IMODE((run / "00 Dashboard.md").stat().st_mode) == 0o600

    # every wikilink must point at an existing note
    broken = []
    for note in vault.rglob("*.md"):
        for target in LINK.findall(note.read_text()):
            if not (vault / f"{target}.md").is_file():
                broken.append(f"{note.name} -> {target}")
    assert not broken, broken

    dashboard = (run / "00 Dashboard.md").read_text()
    assert dashboard.startswith("---\n") and "critical: 3" in dashboard


def test_second_scan_shows_new_and_resolved(fake_root: Path, runner: FakeRunner,
                                            tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    VaultWriter(vault).write(_audit(fake_root, runner))
    # fix one issue (redis) and introduce another (telnet)
    runner.responses[("ss", "-H", "-tulpn")] = (
        0, "tcp LISTEN 0 10 0.0.0.0:23 0.0.0.0:*\n", "")
    run2 = VaultWriter(vault).write(_audit(fake_root, runner))
    dash = (run2 / "00 Dashboard.md").read_text()
    assert "Changes since previous scan" in dash
    assert "Telnet" in dash and "~~Redis (often unauthenticated)" in dash
    history = (vault / "Audit History.md").read_text()
    assert history.count("00 Dashboard\\|") == 2
    assert run2.name.endswith("(2)") or run2.name != next(
        p.name for p in vault.iterdir() if p.is_dir() and p != run2)


def test_writer_refuses_symlinked_files(fake_root: Path, runner: FakeRunner,
                                        tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    vault.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("original")
    (vault / "Audit History.md").symlink_to(victim)
    VaultWriter(vault).write(_audit(fake_root, runner))
    assert victim.read_text() == "original"          # symlink replaced, target untouched
    assert not (vault / "Audit History.md").is_symlink()


def test_findings_json_is_machine_readable(fake_root: Path, runner: FakeRunner,
                                           tmp_path: Path) -> None:
    run = VaultWriter(tmp_path / "v").write(_audit(fake_root, runner))
    data = json.loads((run / "findings.json").read_text())
    assert data["summary"]["critical"] == 3
    assert all({"id", "key", "severity"} <= f.keys() for f in data["findings"])


def test_documents_dir_honours_xdg(tmp_path: Path) -> None:
    cfg = tmp_path / ".config"
    cfg.mkdir()
    (cfg / "user-dirs.dirs").write_text('XDG_DOCUMENTS_DIR="$HOME/Dokumente"\n')
    assert documents_dir(tmp_path) == tmp_path / "Dokumente"
    assert documents_dir(tmp_path / "nohome") == tmp_path / "nohome" / "Documents"
