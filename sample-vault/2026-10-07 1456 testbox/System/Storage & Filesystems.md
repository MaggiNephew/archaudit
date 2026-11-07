---
title: "Storage & Filesystems"
type: "system"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
category: "Filesystem"
findings: 2
tags:
  - "archaudit"
  - "archaudit/system"
  - "filesystem"
  - "storage"
  - "filesystem"
  - "encryption"
---

# Storage & Filesystems

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


_1 disk(s), root encrypted: no_

> [!note] 2 finding(s) in this area
> - 🟦 **Low** · [[2026-10-07 1456 testbox/Findings/L01 Root filesystem is not encrypted|L01 Root filesystem is not encrypted]]
> - 🟦 **Low** · [[2026-10-07 1456 testbox/Findings/L02 Temporary-shared mounts lack hardening options|L02 Temporary/shared mounts lack hardening options]]

## Block devices

| Device | Type | Size | FS | Mounted on | Model |
|---|---|---|---|---|---|
| nvme0n1 | disk | 953.9G | — | — | Samsung SSD 980 PRO 1TB |
| └ nvme0n1p1 | part | 1G | vfat | /boot | — |
| └ nvme0n1p2 | part | 952.9G | ext4 | / | — |

| Item | Value |
|---|---|
| Root filesystem encrypted (LUKS/dm-crypt) | no |

## Disk usage

| Mount | FS | Size | Used |
|---|---|---|---|
| / | ext4 | 252.0 GiB | 88% |

## Mount hardening

| Mount | Status | Recommended options | Missing |
|---|---|---|---|
| /tmp | mounted | nosuid, nodev | nodev |
| /dev/shm | not a separate mount | nosuid, nodev, noexec | — |
| /var/tmp | not a separate mount | nosuid, nodev | — |
| /home | not a separate mount | nosuid, nodev | — |

| Item | Value |
|---|---|
| Swap devices | none |
