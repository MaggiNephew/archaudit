from pathlib import Path

import pytest

from archaudit import md
from archaudit.collectors.kernel import SYSCTL_CHECKS
from archaudit.collectors.network import parse_ss, parse_sshd_config
from archaudit.collectors.packages import (
    last_full_upgrade,
    parse_arch_audit,
    parse_pacman_conf,
    siglevel_risk,
)
from archaudit.collectors.users import password_state
from archaudit.core import Context, Severity


def test_parse_arch_audit_variants() -> None:
    text = (
        "Package curl is affected by CVE-2023-38545, CVE-2023-38546. High risk! Update to 8.4.0-1!\n"
        "Package libxml2 is affected by denial of service. Medium risk!\n"
        "Package tiff is affected by CVE-2017-9935. Critical risk!. Update to 4.0.9-1!\n"
        "Package x is affected by CVE-2024-1. Low risk! Update to at least 2.0-1!\n"
        "\x1b[31mPackage y is affected by CVE-2024-2. Unknown risk!\x1b[0m\n"
        "Package z is affected by CVE-2024-3. High risk! Update to 1.1-1 from testing repos!\n"
        "something unexpected\n"
    )
    pkgs, unparsed = parse_arch_audit(text)
    by = {p.name: p for p in pkgs}
    assert by["curl"].cves == ("CVE-2023-38545", "CVE-2023-38546")
    assert by["curl"].severity is Severity.HIGH and by["curl"].fixed_version == "8.4.0-1"
    assert by["libxml2"].fixed_version is None and by["libxml2"].issues == "denial of service"
    assert by["tiff"].severity is Severity.CRITICAL and by["tiff"].fixed_version == "4.0.9-1"
    assert by["x"].fixed_version == "2.0-1"
    assert by["y"].severity is Severity.LOW
    assert by["z"].fix_in_testing
    assert unparsed == ["something unexpected"]


@pytest.mark.parametrize(("value", "expected"), [
    ("Required DatabaseOptional", None),
    ("Never", Severity.HIGH),
    ("PackageNever", Severity.HIGH),
    ("DatabaseNever", Severity.LOW),
    ("Optional TrustAll", Severity.MEDIUM),
    ("Required DatabaseTrustAll", None),
])
def test_siglevel_risk(value: str, expected: Severity | None) -> None:
    risk = siglevel_risk(value)
    assert (risk[0] if risk else None) == expected


def test_parse_pacman_conf_keeps_sections_and_comments() -> None:
    conf = parse_pacman_conf("[options]\nSigLevel = Required # comment\n[core]\n"
                             "Include = /etc/pacman.d/mirrorlist\n")
    assert conf["options"]["SigLevel"] == ["Required"]
    assert "core" in conf


def test_last_full_upgrade_both_timestamp_formats() -> None:
    log = ("[2019-03-01 10:00] [PACMAN] starting full system upgrade\n"
           "[2026-09-30T08:15:00+0200] [PACMAN] starting full system upgrade\n"
           "[2026-10-01T09:00:00+0200] [PACMAN] Running 'pacman -S vim'\n")
    when = last_full_upgrade(log)
    assert when is not None and (when.year, when.month, when.day) == (2026, 9, 30)
    assert last_full_upgrade("nothing here") is None


def test_parse_ss() -> None:
    out = parse_ss('tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
                   "tcp LISTEN 0 4096 [::1]:5432 [::]:*\n"
                   "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
                   "tcp LISTEN 0 128 *:631 *:*\n"
                   "garbage\n")
    by_port = {x.port: x for x in out}
    assert by_port[22].process == "sshd" and by_port[22].exposed
    assert by_port[5432].scope == "localhost" and not by_port[5432].exposed
    assert by_port[53].address == "127.0.0.53"
    assert by_port[631].scope == "all interfaces"


def test_sshd_config_first_match_wins_with_include_and_match(fake_root: Path) -> None:
    opts = parse_sshd_config(Context(root=fake_root, is_root=False))
    # Include comes first in the file, so its PermitRootLogin wins.
    assert opts["permitrootlogin"] == "yes"
    assert opts["passwordauthentication"] == "no"   # Match block ignored
    assert opts["x11forwarding"] == "yes"


@pytest.mark.parametrize(("field", "state"), [
    ("", "EMPTY"), ("!", "locked"), ("!$6$x", "locked"), ("*", "locked"),
    ("$y$j9T$a$b", "yescrypt"), ("$6$a$b", "SHA-512"), ("$1$a$b", "MD5 (weak)"),
])
def test_password_state(field: str, state: str) -> None:
    assert password_state(field) == state


def test_sysctl_comparisons() -> None:
    checks = {c.key: c for c in SYSCTL_CHECKS}
    assert checks["kernel.randomize_va_space"].passes("2")
    assert not checks["kernel.randomize_va_space"].passes("1")
    assert checks["kernel.kptr_restrict"].passes("2")
    assert not checks["kernel.kptr_restrict"].passes("garbage")


def test_markdown_helpers() -> None:
    assert md.safe_filename('a/b:c*?"<>|#^[x]') == "a-b-c---------x"
    assert md.cell("a|b\nc") == "a\\|b<br>c"
    fenced = md.code("before\n```\ninside\n```")
    assert fenced.startswith("````text") and fenced.endswith("````")
    assert md.callout("info", "T", "line1\n\nline2") == "> [!info] T\n> line1\n>\n> line2"
    assert md.frontmatter({"a": 'x"y', "n": 3, "t": ["p"]}) == \
        '---\na: "x\\"y"\nn: 3\nt:\n  - "p"\n---'
