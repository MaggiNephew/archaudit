---
title: "Command Log"
type: "index"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
tags:
  - "archaudit"
  - "archaudit/index"
  - "raw"
---

# Command Log

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


Raw output of the main commands, for reference and diffing.

| Output | Command | Status | Time |
|---|---|---|---|
| [[2026-10-07 1456 testbox/Raw/timedatectl\|timedatectl]] | `timedatectl show` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/lscpu\|lscpu]] | `lscpu -J` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/lspci\|lspci]] | `lspci` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/lsusb\|lsusb]] | `lsusb` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/pacman -Q\|pacman -Q]] | `pacman -Q` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/checkupdates\|checkupdates]] | `checkupdates` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/arch-audit\|arch-audit]] | `arch-audit --show-cve` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/ip addr\|ip addr]] | `ip -j addr show` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/ip route\|ip route]] | `ip -j route show` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/ss -tulpn\|ss -tulpn]] | `ss -H -tulpn` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/last\|last]] | `last -n 20 -w` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/running services\|running services]] | `systemctl list-units --type=service --state=running --no-legend --plain --no-pager` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/timers\|timers]] | `systemctl list-timers --all --no-legend --no-pager` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/lsblk\|lsblk]] | `lsblk -J -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,RO,RM` | ok | 0.01s |
| [[2026-10-07 1456 testbox/Raw/journal errors\|journal errors]] | `journalctl -q --no-pager -b -p 3 -o short-iso -n 200` | ok | 0.01s |
