"""Collector registry. Order matters: later collectors may use facts
(``ctx.facts``) recorded by earlier ones (e.g. CPU vendor, laptop)."""

from __future__ import annotations

from archaudit.collectors.filesystem import collect_filesystem
from archaudit.collectors.kernel import collect_kernel
from archaudit.collectors.logs import collect_logs
from archaudit.collectors.network import collect_network
from archaudit.collectors.packages import collect_packages
from archaudit.collectors.services import collect_services
from archaudit.collectors.system import collect_hardware, collect_overview
from archaudit.collectors.users import collect_users
from archaudit.core import Collector

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

__all__ = ["COLLECTORS"]
