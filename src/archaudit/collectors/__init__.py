"""Collector registries per operating system. Order matters: later
collectors may use facts (``ctx.facts``) recorded by earlier ones (e.g. CPU
vendor, laptop)."""

from __future__ import annotations

from archaudit.collectors.filesystem import collect_filesystem
from archaudit.collectors.kernel import collect_kernel
from archaudit.collectors.logs import collect_logs
from archaudit.collectors.network import collect_network
from archaudit.collectors.packages import collect_packages
from archaudit.collectors.services import collect_services
from archaudit.collectors.system import collect_hardware, collect_overview
from archaudit.collectors.users import collect_users
from archaudit.collectors.windows import WINDOWS
from archaudit.core import Collector
from archaudit.platforms import Platform

COLLECTORS: dict[str, Collector] = {
    "overview": collect_overview,
    "hardware": collect_hardware,
    "kernel": collect_kernel,
    "packages": collect_packages,
    "network": collect_network,
    "users": collect_users,
    "services": collect_services,
    "filesystem": collect_filesystem,
    "logs": collect_logs,
}

LINUX_COLLECTORS = COLLECTORS
WINDOWS_COLLECTORS: dict[str, Collector] = WINDOWS


def collectors_for(platform: Platform) -> dict[str, Collector]:
    return WINDOWS_COLLECTORS if platform.is_windows else LINUX_COLLECTORS


__all__ = ["COLLECTORS", "LINUX_COLLECTORS", "WINDOWS_COLLECTORS", "collectors_for"]
