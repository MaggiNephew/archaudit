"""Test fixtures: a fake Arch filesystem root and a scripted command runner."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from archaudit.core import CmdStatus, CommandResult

RECENT = (datetime.now() - timedelta(days=45)).strftime("%Y-%m-%dT%H:%M:%S+0000")


class FakeRunner:
    """Answers commands from a table keyed by the argv tuple."""

    def __init__(self, responses: dict[tuple[str, ...], tuple[int, str, str]],
                 installed: set[str]) -> None:
        self.responses = responses
        self.installed = installed
        self.calls: list[tuple[str, ...]] = []

    def which(self, name: str) -> str | None:
        return f"/usr/bin/{name}" if name in self.installed else None

    def run(self, argv: Sequence[str], timeout: float,
            ok_codes: Sequence[int]) -> CommandResult:
        args = tuple(argv)
        self.calls.append(args)
        if args[0] not in self.installed:
            return CommandResult(args, CmdStatus.MISSING)
        rc, out, err = self.responses.get(args, (0, "", ""))
        status = CmdStatus.OK if rc in ok_codes else (
            CmdStatus.DENIED if "Permission denied" in err else CmdStatus.FAILED)
        return CommandResult(args, status, rc, out, err, 0.01)


FILES = {
    "etc/os-release": 'NAME="Arch Linux"\nPRETTY_NAME="Arch Linux"\nID=arch\nBUILD_ID=rolling\n',
    "etc/hostname": "testbox\n",
    "etc/passwd": "root:x:0:0::/root:/bin/bash\n"
                  "toor:x:0:0::/root:/bin/bash\n"
                  "bin:x:1:1::/:/usr/bin/nologin\n"
                  "git:x:970:970::/var/lib/git:/bin/bash\n"
                  "alice:x:1000:1000::/home/alice:/bin/zsh\n"
                  "bob:x:1001:1001::/home/bob:/bin/bash\n",
    "etc/group": "root:x:0:root\nwheel:x:998:alice\ndocker:x:969:bob\nalice:x:1000:\n",
    "etc/shadow": "root:!*:19000::::::\ntoor:$1$abc$def:19000::::::\n"
                  "alice:$y$j9T$salt$hash:19000:0:99999:7:::\nbob::19000::::::\n",
    "etc/sudoers": "root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) NOPASSWD: ALL\n"
                   "@includedir /etc/sudoers.d\n",
    "etc/pacman.conf": "[options]\nHoldPkg = pacman glibc\nIgnorePkg = linux\n"
                       "SigLevel = Required DatabaseOptional\n\n"
                       "[core]\nInclude = /etc/pacman.d/mirrorlist\n\n"
                       "[myrepo]\nSigLevel = Never\nServer = http://repo.example/$arch\n",
    "etc/pacman.d/mirrorlist": "## mirrors\nServer = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n"
                               "Server = http://mirror.example/$repo/os/$arch\n"
                               "#Server = http://commented.example/\n",
    "etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n"
                           "PermitRootLogin no\nPasswordAuthentication no\n"
                           "Match User backup\n  PasswordAuthentication yes\n",
    "etc/ssh/sshd_config.d/10-custom.conf": "PermitRootLogin yes\nX11Forwarding yes\n",
    "usr/bin/sshd": "",
    "var/log/pacman.log": f"[2020-01-01T10:00:00+0000] [PACMAN] starting full system upgrade\n"
                          f"[{RECENT}] [PACMAN] starting full system upgrade\n"
                          f"[{RECENT}] [ALPM] upgraded curl (8.0-1 -> 8.1-1)\n",
    "proc/sys/kernel/osrelease": "6.10.1-arch1-1\n",
    "proc/cmdline": "root=/dev/sda2 rw mitigations=off quiet\n",
    "proc/sys/kernel/randomize_va_space": "2\n",
    "proc/sys/kernel/kptr_restrict": "0\n",
    "proc/sys/kernel/unprivileged_bpf_disabled": "2\n",
    "proc/sys/fs/protected_symlinks": "1\n",
    "proc/cpuinfo": "vendor_id\t: GenuineIntel\nmodel name\t: Test CPU\n",
    "proc/meminfo": "MemTotal:       16000000 kB\nMemAvailable:    8000000 kB\n",
    "proc/mounts": "/dev/sda2 / ext4 rw,relatime 0 0\ntmpfs /tmp tmpfs rw,nosuid 0 0\n",
    "sys/devices/system/cpu/vulnerabilities/meltdown": "Not affected\n",
    "sys/devices/system/cpu/vulnerabilities/spectre_v2": "Vulnerable\n",
    "sys/devices/system/cpu/vulnerabilities/mds": "Mitigation: Clear CPU buffers\n",
    "usr/lib/modules/6.11.0-arch1-1/.keep": "",
}

ARCH_AUDIT = (
    "Package curl is affected by CVE-2023-38545, CVE-2023-38546. High risk! Update to 8.4.0-1!\n"
    "Package libxml2 is affected by CVE-2024-0001. Medium risk!\n"
    "Package openssl is affected by CVE-2024-9999. Critical risk! "
    "Update to 3.3.2-1 from testing repos!\n"
)

RESPONSES: dict[tuple[str, ...], tuple[int, str, str]] = {
    ("pacman", "-Q"): (0, "curl 8.1-1\nlinux 6.11.0.arch1-1\nopenssl 3.3.1-1\nyay-bin 12.0-1\n", ""),
    ("pacman", "-Qe"): (0, "curl 8.1-1\nlinux 6.11.0.arch1-1\nyay-bin 12.0-1\n", ""),
    ("pacman", "-Qm"): (0, "yay-bin 12.0-1\n", ""),
    ("pacman", "-Qdtq"): (1, "", ""),
    ("pacman", "-Q", "linux", "linux-lts", "linux-zen", "linux-hardened", "linux-rt"):
        (1, "linux 6.11.0.arch1-1\n", "error: package 'linux-lts' was not found\n"),
    ("pacman", "-Q", "intel-ucode"): (1, "", "error: package 'intel-ucode' was not found\n"),
    ("pacman", "-Qk"): (1, "curl: 100 total files, 1 missing file\n",
                        "warning: curl: /usr/share/doc/curl/README (No such file or directory)\n"),
    ("arch-audit", "--show-cve"): (0, ARCH_AUDIT, ""),
    ("checkupdates",): (0, "curl 8.1-1 -> 8.4.0-1\nlinux 6.11.0.arch1-1 -> 6.11.1.arch1-1\n", ""),
    ("ss", "-H", "-tulpn"): (0,
        'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
        'tcp LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=1,fd=4))\n'
        'tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=9,fd=6))\n'
        "tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*\n"
        "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n", ""),
    ("systemctl", "is-active", "--", "sshd.service", "ssh.service"): (3, "active\ninactive\n", ""),
    ("systemctl", "is-enabled", "--", "sshd.service", "ssh.service"): (1, "enabled\nnot-found\n", ""),
    ("journalctl", "-q", "--no-pager", "-o", "cat", "--since", "-30d", "-u", "sshd.service",
     "-u", "ssh.service"): (0,
        "".join(f"Failed password for invalid user admin from 203.0.113.{i % 3} port 22 ssh2\n"
                for i in range(25)) + "Accepted publickey for alice from 192.0.2.5 port 50 ssh2\n",
        ""),
}

INSTALLED = {"pacman", "arch-audit", "checkupdates", "ss", "systemctl", "journalctl"}


RESPONSES.update({
    ("timedatectl", "show"): (0, "Timezone=Europe/Berlin\nNTP=yes\nNTPSynchronized=yes\n", ""),
    ("lscpu", "-J"): (0, '{"lscpu": [{"field": "Architecture:", "data": "x86_64"}, {"field": "CPU(s):", "data": "16"}, {"field": "Vendor ID:", "data": "GenuineIntel"}, {"field": "Model name:", "data": "12th Gen Intel(R) Core(TM) i7-1260P"}, {"field": "Thread(s) per core:", "data": "2"}, {"field": "CPU max MHz:", "data": "4700.0000"}]}', ""),
    ("ip", "-j", "addr", "show"): (0, '[{"ifname": "lo", "operstate": "UNKNOWN", "address": "00:00:00:00:00:00", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]}, {"ifname": "wlan0", "operstate": "UP", "address": "3c:a9:f4:12:34:56", "addr_info": [{"local": "192.168.1.42", "prefixlen": 24}, {"local": "fe80::1", "prefixlen": 64}]}]', ""),
    ("ip", "-j", "route", "show"): (0, '[{"dst": "default", "gateway": "192.168.1.1", "dev": "wlan0", "protocol": "dhcp"}, {"dst": "192.168.1.0/24", "dev": "wlan0", "protocol": "kernel"}]', ""),
    ("lsblk", "-J", "-o", "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,RO,RM"): (0, '{"blockdevices": [{"name": "nvme0n1", "type": "disk", "size": "953.9G", "fstype": null, "mountpoints": [null], "model": "Samsung SSD 980 PRO 1TB", "children": [{"name": "nvme0n1p1", "type": "part", "size": "1G", "fstype": "vfat", "mountpoints": ["/boot"]}, {"name": "nvme0n1p2", "type": "part", "size": "952.9G", "fstype": "ext4", "mountpoints": ["/"]}]}]}', ""),
    ("lspci",): (0, "00:02.0 VGA compatible controller: Intel Corporation Alder Lake-P GT2\n"
                    "00:14.3 Network controller: Intel Corporation Alder Lake-P PCH CNVi WiFi\n", ""),
    ("lsusb",): (0, "Bus 001 Device 002: ID 8087:0033 Intel Corp. AX211 Bluetooth\n", ""),
    ("last", "-n", "20", "-w"): (0, "alice    tty1         Tue Oct  6 08:01   still logged in\n", ""),
})
INSTALLED.update({"timedatectl", "lscpu", "ip", "lsblk", "lspci", "lsusb", "last"})


@pytest.fixture
def fake_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    for rel, content in FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    (root / "home" / "alice").mkdir(parents=True)
    (root / "home" / "alice").chmod(0o755)
    return root


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner(dict(RESPONSES), set(INSTALLED))
