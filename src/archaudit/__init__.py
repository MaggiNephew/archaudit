"""archaudit - read-only security and inventory audit for Arch Linux.

Collects as much system information as the current privileges allow, runs
defensive security checks (vulnerable packages, pending updates, kernel and
CPU mitigations, sysctl hardening, SSH, firewall, accounts, SUID files, ...)
and writes everything as an Obsidian-friendly Markdown vault, including an
explicit list of what could *not* be collected and how to fix that.

The tool never changes system state: it only reads files and runs query
commands with fixed arguments.
"""

__all__ = ["__version__"]

__version__ = "1.0.0"
