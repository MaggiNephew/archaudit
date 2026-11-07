---
title: "L02 · Temporary/shared mounts lack hardening options"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "L02"
severity: "low"
severity_rank: 2
category: "Filesystem"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/low"
  - "category/filesystem"
---

# L02 · Temporary/shared mounts lack hardening options

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!note] 🟦 Low — Filesystem
> `nosuid`/`nodev`/`noexec` on world-writable mounts limit what an attacker can do with files dropped there.

## Evidence

```text
/tmp: missing nodev
```

## How to fix

Add the options in `/etc/fstab` (or a systemd mount drop-in for /tmp) and remount.

Found by: [[2026-10-07 1456 testbox/System/Storage & Filesystems|Storage & Filesystems]]
