"""Which operating system and distribution family the audit runs on.

Collectors use this to pick package-manager backends, unit names and fix
hints. Detection only reads ``/etc/os-release`` (Linux) or asks Python which
OS it is running on; it never runs commands.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

# os-release IDs (from ID or ID_LIKE) -> family
_FAMILIES: dict[str, str] = {
    "arch": "arch", "archarm": "arch", "manjaro": "arch", "endeavouros": "arch",
    "cachyos": "arch", "garuda": "arch", "artix": "arch",
    "debian": "debian", "ubuntu": "debian", "linuxmint": "debian", "pop": "debian",
    "kali": "debian", "raspbian": "debian", "elementary": "debian", "zorin": "debian",
    "fedora": "fedora", "rhel": "fedora", "centos": "fedora", "rocky": "fedora",
    "almalinux": "fedora", "ol": "fedora", "nobara": "fedora",
}

# Which package provides a command, per family, for "how to fix" hints.
_PACKAGE_FOR_COMMAND: dict[str, dict[str, str]] = {
    "arch": {
        "arch-audit": "arch-audit", "checkupdates": "pacman-contrib", "lspci": "pciutils",
        "lsusb": "usbutils", "ss": "iproute2", "ip": "iproute2", "lsblk": "util-linux",
        "lscpu": "util-linux", "last": "util-linux", "bootctl": "systemd",
        "nft": "nftables", "flatpak": "flatpak", "sshd": "openssh",
        "timedatectl": "systemd", "systemctl": "systemd", "journalctl": "systemd",
        "coredumpctl": "systemd",
    },
    "debian": {
        "debsecan": "debsecan", "lspci": "pciutils", "lsusb": "usbutils", "ss": "iproute2",
        "ip": "iproute2", "lsblk": "util-linux", "lscpu": "util-linux", "last": "wtmpdb",
        "bootctl": "systemd-boot", "nft": "nftables", "flatpak": "flatpak",
        "sshd": "openssh-server", "coredumpctl": "systemd-coredump",
    },
    "fedora": {
        "lspci": "pciutils", "lsusb": "usbutils", "ss": "iproute", "ip": "iproute",
        "lsblk": "util-linux", "lscpu": "util-linux", "last": "util-linux",
        "nft": "nftables", "flatpak": "flatpak", "sshd": "openssh-server",
        "coredumpctl": "systemd-udev",
    },
}

_INSTALL = {"arch": "sudo pacman -S", "debian": "sudo apt install", "fedora": "sudo dnf install"}


@dataclass(frozen=True, slots=True)
class Platform:
    os: str         # "linux" or "windows"
    family: str     # "arch", "debian", "fedora", "linux" (unknown distro) or "windows"
    name: str = ""  # human readable, e.g. "Ubuntu 24.04.1 LTS"
    distro_id: str = ""

    @property
    def is_windows(self) -> bool:
        return self.os == "windows"

    @property
    def install_cmd(self) -> str:
        return _INSTALL.get(self.family, "")

    @property
    def elevate_hint(self) -> str:
        if self.is_windows:
            return "Re-run from a terminal opened with **Run as administrator**"
        return "Re-run with `sudo archaudit`"

    def package_for(self, command: str) -> str | None:
        return _PACKAGE_FOR_COMMAND.get(self.family, {}).get(command)

    def install_hint(self, command: str) -> tuple[str, str]:
        """(fix text, package name or "") for a missing command."""
        pkg = self.package_for(command)
        if pkg and self.install_cmd:
            return f"`{self.install_cmd} {pkg}`", pkg
        return f"install `{command}`", ""


def parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def family_of(os_release: dict[str, str]) -> str:
    ids = [os_release.get("ID", ""), *os_release.get("ID_LIKE", "").split()]
    for distro in ids:
        if distro in _FAMILIES:
            return _FAMILIES[distro]
    return "linux"


def detect(root: Path = Path("/"), system: str | None = None) -> Platform:
    system = system or sys.platform
    if system.startswith("win"):
        return Platform("windows", "windows", "Windows", "windows")
    text = ""
    for rel in ("etc/os-release", "usr/lib/os-release"):
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
            break
        except OSError:
            continue
    osr = parse_os_release(text)
    return Platform("linux", family_of(osr), osr.get("PRETTY_NAME", osr.get("ID", "Linux")),
                    osr.get("ID", ""))


def is_admin() -> bool:
    """root on Linux; an elevated token on Windows."""
    if sys.platform == "win32":
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0
