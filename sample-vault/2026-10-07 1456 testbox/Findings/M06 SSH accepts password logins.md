---
title: "M06 · SSH accepts password logins"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "M06"
severity: "medium"
severity_rank: 3
category: "Network"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/medium"
  - "category/network"
---

# M06 · SSH accepts password logins

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!warning] 🟨 Medium — Network
> Password or keyboard-interactive authentication is enabled (OpenSSH's default when unset), so the server can be brute-forced.

## Evidence

```text
PasswordAuthentication=no, KbdInteractiveAuthentication=yes
```

## How to fix

Set up key-based login first, then set `PasswordAuthentication no` and `KbdInteractiveAuthentication no`; consider `fail2ban`/`sshguard`.

## References

- <https://wiki.archlinux.org/title/OpenSSH#Protection>

Found by: [[2026-10-07 1456 testbox/System/SSH Server|SSH Server]]
