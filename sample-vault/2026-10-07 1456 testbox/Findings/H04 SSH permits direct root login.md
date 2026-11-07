---
title: "H04 · SSH permits direct root login"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "H04"
severity: "high"
severity_rank: 4
category: "Network"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/high"
  - "category/network"
---

# H04 · SSH permits direct root login

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 🟧 High — Network
> Root can log in directly over SSH, making root the prime brute-force target and removing per-user accountability.

## How to fix

Set `PermitRootLogin no` in `/etc/ssh/sshd_config.d/10-hardening.conf` and `sudo systemctl restart sshd`.

## References

- <https://wiki.archlinux.org/title/OpenSSH#Protection>

Found by: [[2026-10-07 1456 testbox/System/SSH Server|SSH Server]]
