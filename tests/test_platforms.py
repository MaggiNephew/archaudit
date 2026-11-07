"""Platform detection, Debian/Fedora parsers, and end-to-end Ubuntu/Fedora audits."""

from datetime import datetime
from pathlib import Path

import pytest
from conftest import FakeRunner

from archaudit.cli import run_audit
from archaudit.collectors import COLLECTORS
from archaudit.collectors._pkg import parse_verify
from archaudit.collectors.pkg_apt import (
    is_security_source,
    last_apt_upgrade,
    parse_simulated_upgrade,
    parse_sources,
)
from archaudit.collectors.pkg_dnf import (
    parse_check_update,
    parse_repo_files,
    parse_security_advisories,
)
from archaudit.core import Context, GapKind, Severity
from archaudit.platforms import Platform, detect, family_of


@pytest.mark.parametrize(("osr", "family"), [
    ({"ID": "arch"}, "arch"),
    ({"ID": "cachyos", "ID_LIKE": "arch"}, "arch"),
    ({"ID": "ubuntu", "ID_LIKE": "debian"}, "debian"),
    ({"ID": "kali", "ID_LIKE": "debian"}, "debian"),
    ({"ID": "linuxmint", "ID_LIKE": "ubuntu debian"}, "debian"),
    ({"ID": "fedora"}, "fedora"),
    ({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}, "fedora"),
    ({"ID": "nixos"}, "linux"),
])
def test_family_of(osr: dict[str, str], family: str) -> None:
    assert family_of(osr) == family


def test_detect(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text('ID=ubuntu\nID_LIKE=debian\n'
                                                 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\n')
    p = detect(tmp_path, system="linux")
    assert (p.family, p.name, p.install_cmd) == ("debian", "Ubuntu 24.04.1 LTS",
                                                 "sudo apt install")
    w = detect(tmp_path, system="win32")
    assert w.is_windows and "administrator" in w.elevate_hint
    assert detect(tmp_path / "missing", system="linux").family == "linux"


def test_install_hints() -> None:
    assert Platform("linux", "debian").install_hint("lsusb") == ("`sudo apt install usbutils`",
                                                                 "usbutils")
    assert Platform("linux", "arch").install_hint("checkupdates")[1] == "pacman-contrib"
    assert Platform("linux", "linux").install_hint("lsusb") == ("install `lsusb`", "")


def test_apt_parsers() -> None:
    sim = ("NOTE: This is only a simulation!\n"
           "Inst openssl [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-security "
           "[amd64])\n"
           "Inst vim [2:9.1.0016-1] (2:9.1.0016-1ubuntu7.2 Ubuntu:24.04/noble-updates [amd64])\n"
           "Inst newpkg (1.0-1 Debian:12.5/stable [all])\n"
           "Conf openssl (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-security [amd64])\n")
    rows = parse_simulated_upgrade(sim)
    assert [r[0] for r in rows] == ["openssl", "vim", "newpkg"]
    assert rows[0][1:3] == ("3.0.13-0ubuntu3.1", "3.0.13-0ubuntu3.4")
    assert rows[2][1] == ""
    assert is_security_source(rows[0][3]) and not is_security_source(rows[1][3])
    assert is_security_source("Debian-Security:12/stable-security")

    log = ("Start-Date: 2026-09-01  10:00:00\nCommandline: apt install htop\nInstall: htop\n"
           "End-Date: 2026-09-01  10:00:05\n\n"
           "Start-Date: 2026-09-20  08:30:00\nCommandline: apt full-upgrade\n"
           "Upgrade: openssl:amd64 (3.0.13-1, 3.0.13-2)\nEnd-Date: 2026-09-20  08:31:00\n\n"
           "Start-Date: 2026-10-01  09:00:00\nCommandline: apt remove x\nRemove: x\n")
    assert last_apt_upgrade(log) == datetime(2026, 9, 20, 8, 30)
    assert last_apt_upgrade("") is None

    sources = parse_sources({
        "/etc/apt/sources.list": "deb http://deb.debian.org/debian bookworm main\n"
                                 "# deb http://old.example/ x main\n"
                                 "deb [arch=amd64 trusted=yes] http://repo.example/ ./\n",
        "/etc/apt/sources.list.d/ubuntu.sources":
            "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\nSuites: noble\n\n"
            "Types: deb\nURIs: https://x.example/\nEnabled: no\n\n"
            "Types: deb\nURIs: https://y.example/\nTrusted: yes\n",
    })
    by_uri = {u: o for _, u, o in sources}
    assert set(by_uri) == {"http://deb.debian.org/debian", "http://repo.example/",
                           "http://archive.ubuntu.com/ubuntu", "https://y.example/"}
    assert "trusted=yes" in by_uri["http://repo.example/"]
    assert by_uri["https://y.example/"] == ["trusted=yes"]


def test_dnf_parsers() -> None:
    upd = ("\nkernel.x86_64    6.11.4-301.fc41    updates\n"
           "openssl-libs.x86_64   1:3.2.2-9.fc41  updates\n"
           "Obsoleting Packages\ngrub2-tools.x86_64  1:2.12-10.fc41  updates\n")
    assert [r[0] for r in parse_check_update(upd)] == ["kernel.x86_64", "openssl-libs.x86_64"]

    dnf4 = ("FEDORA-2026-1a2b3c Important/Sec. openssl-libs-1:3.2.2-9.fc41.x86_64\n"
            "FEDORA-2026-ffff Moderate/Sec.  curl-8.9.1-2.fc41.x86_64\n")
    dnf5 = ("Name               Type     Severity  Package                         Issued\n"
            "FEDORA-2026-9999   security Critical  kernel-6.11.4-301.fc41.x86_64  2026-10-01\n")
    a4 = parse_security_advisories(dnf4)
    assert [(a, s) for a, s, _ in a4] == [("FEDORA-2026-1a2b3c", Severity.HIGH),
                                          ("FEDORA-2026-ffff", Severity.MEDIUM)]
    assert a4[0][2] == "openssl-libs-1:3.2.2-9.fc41.x86_64"
    a5 = parse_security_advisories(dnf5)
    assert a5 == [("FEDORA-2026-9999", Severity.CRITICAL, "kernel-6.11.4-301.fc41.x86_64")]

    repos = parse_repo_files({"/etc/yum.repos.d/x.repo":
                              "[fedora]\nenabled=1\ngpgcheck=1\n[evil]\ngpgcheck=0\n"})
    assert [(s, o.get("gpgcheck")) for _, s, o in repos] == [("fedora", "1"), ("evil", "0")]


def test_parse_verify() -> None:
    out = ("??5??????   /usr/bin/tampered\n"
           "??5?????? c /etc/ssh/sshd_config\n"
           "S.5....T.  c /etc/sudoers\n"
           "missing     /usr/share/doc/x/README\n"
           "missing   d /usr/share/man/man1/y.1.gz\n"
           ".M.......    /usr/lib/perms-only\n")
    missing, modified = parse_verify(out)
    assert missing == ["/usr/share/doc/x/README", "/usr/share/man/man1/y.1.gz"]
    assert modified == ["/usr/bin/tampered"]


# --------------------------------------------------------------------------- Ubuntu e2e

UBUNTU_FILES = {
    "etc/os-release": 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_CODENAME=noble\n'
                      'PRETTY_NAME="Ubuntu 24.04.1 LTS"\n',
    "etc/hostname": "ubox\n",
    "etc/passwd": "root:x:0:0::/root:/bin/bash\nsam:x:1000:1000::/home/sam:/bin/bash\n",
    "etc/group": "sudo:x:27:sam\nadm:x:4:sam\n",
    "etc/apt/sources.list.d/ubuntu.sources": "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\n"
                                             "Suites: noble noble-updates\n",
    "etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Update-Package-Lists "1";\n'
                                          'APT::Periodic::Unattended-Upgrade "0";\n',
    "var/log/apt/history.log": "",
    "run/reboot-required": "*** System restart required ***\n",
    "run/reboot-required.pkgs": "linux-image-6.8.0-48-generic\n",
    "proc/sys/kernel/osrelease": "6.8.0-45-generic\n",
    "sys/kernel/security/lsm": "lockdown,capability,landlock,yama\n",
    "lib/modules/6.8.0-45-generic/.keep": "",
    "lib/modules/6.8.0-48-generic/.keep": "",
    "proc/mounts": "/dev/sda2 / ext4 rw 0 0\n",
}

UBUNTU_RESPONSES: dict[tuple[str, ...], tuple[int, str, str]] = {
    ("dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Package} ${Version}\\n"):
        (0, "ii  openssl 3.0.13-0ubuntu3.1\nii  vim 2:9.1\nrc  oldpkg 1.0\n", ""),
    ("apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"): (0,
        "Inst openssl [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-security "
        "[amd64])\nInst vim [2:9.1] (2:9.2 Ubuntu:24.04/noble-updates [amd64])\n", ""),
    ("apt-get", "-s", "-o", "Debug::NoLocking=1", "autoremove"): (0, "Remv libold1 [1.0]\n", ""),
    ("apt-mark", "showmanual"): (0, "vim\n", ""),
}


@pytest.fixture
def ubuntu_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    for rel, content in UBUNTU_FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    (root / "home" / "sam").mkdir(parents=True)
    (root / "home" / "sam").chmod(0o700)
    return root


def test_ubuntu_end_to_end(ubuntu_root: Path) -> None:
    runner = FakeRunner(dict(UBUNTU_RESPONSES), {"dpkg", "dpkg-query", "apt-get", "apt-mark"})
    ctx = Context(root=ubuntu_root, runner=runner, is_root=True)
    assert ctx.platform.family == "debian"
    result = run_audit(ctx, list(COLLECTORS))
    t = {f.title: f.severity for f in result.findings}
    assert t["1 security update(s) pending"] is Severity.HIGH
    assert t["1 other package update(s) pending"] is Severity.LOW
    assert t["Automatic security updates are not enabled"] is Severity.LOW
    assert t["Kernel upgraded but system not rebooted"] is Severity.MEDIUM
    assert t["No mandatory access control (AppArmor/SELinux) active"] is Severity.MEDIUM
    assert "1 unneeded package(s) installed" in t
    assert result.facts["pending_updates"] == "2"
    # Ubuntu has no debsecan: that is reported, not silently skipped
    assert any(g.item == "CVE matching (debsecan)" and g.kind is GapKind.NOT_PRESENT
               for g in result.gaps)
    # never suggests pacman on Debian
    blob = " ".join(f.remediation for f in result.findings) + " ".join(g.fix for g in result.gaps)
    assert "pacman" not in blob


def test_fedora_packages_end_to_end(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "etc" / "yum.repos.d").mkdir(parents=True)
    (root / "etc" / "os-release").write_text("ID=fedora\nPRETTY_NAME=\"Fedora Linux 41\"\n")
    (root / "etc" / "yum.repos.d" / "x.repo").write_text("[fedora]\ngpgcheck=1\n"
                                                         "[sketchy]\ngpgcheck=0\n")
    responses: dict[tuple[str, ...], tuple[int, str, str]] = {
        ("rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\\n"): (0, "bash 5.2-1\n", ""),
        ("dnf", "-q", "check-update"): (100, "bash.x86_64  5.2-2.fc41  updates\n", ""),
        ("dnf", "-q", "updateinfo", "list", "--security"):
            (0, "FEDORA-2026-1 Important/Sec. bash-5.2-2.fc41.x86_64\n", ""),
    }
    runner = FakeRunner(responses, {"rpm", "dnf"})
    ctx = Context(root=root, runner=runner, is_root=True)
    result = run_audit(ctx, ["packages"])
    t = {f.title: f.severity for f in result.findings}
    assert t["1 security advisory(ies) pending"] is Severity.HIGH
    assert t["Repositories with package signature checking disabled"] is Severity.HIGH
    assert "1 package update(s) pending" in t

    offline = FakeRunner(responses, {"rpm", "dnf"})
    run_audit(Context(root=root, runner=offline, is_root=True, offline=True), ["packages"])
    assert ("dnf", "-q", "-C", "check-update") in offline.calls  # cache only, no download
