---
title: "L01 · Root filesystem is not encrypted"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "L01"
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

# L01 · Root filesystem is not encrypted

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!note] 🟦 Low — Filesystem
> Anyone with physical access to the disk (theft, repair shop, disposal) can read all data, including SSH keys, browser sessions and password stores.

## How to fix

Full-disk encryption must be set up at install time or by migrating data; see the wiki. At minimum, encrypt sensitive directories and swap.

## References

- <https://wiki.archlinux.org/title/Dm-crypt/Encrypting_an_entire_system>

Found by: [[2026-10-07 1456 testbox/System/Storage & Filesystems|Storage & Filesystems]]
