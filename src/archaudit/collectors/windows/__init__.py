"""Windows collectors (PowerShell / CIM / registry, read-only)."""

from __future__ import annotations

from archaudit.collectors.windows.logs import collect_logs
from archaudit.collectors.windows.network import collect_network
from archaudit.collectors.windows.security import collect_defender, collect_platform_security
from archaudit.collectors.windows.services import collect_services
from archaudit.collectors.windows.storage import collect_storage
from archaudit.collectors.windows.system import collect_hardware, collect_overview
from archaudit.collectors.windows.updates import collect_updates
from archaudit.collectors.windows.users import collect_users
from archaudit.core import Collector

# Area names match the Linux ones where the meaning is the same, so
# `--only network users` works on both.
WINDOWS: dict[str, Collector] = {
    "overview": collect_overview,
    "hardware": collect_hardware,
    "kernel": collect_platform_security,
    "defender": collect_defender,
    "packages": collect_updates,
    "network": collect_network,
    "users": collect_users,
    "services": collect_services,
    "filesystem": collect_storage,
    "logs": collect_logs,
}

__all__ = ["WINDOWS"]
