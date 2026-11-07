---
title: "M10 · sudo rules without password (NOPASSWD)"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "M10"
severity: "medium"
severity_rank: 3
category: "Users & Access"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/medium"
  - "category/users-access"
---

# M10 · sudo rules without password (NOPASSWD)

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!warning] 🟨 Medium — Users & Access
> Any process running as these users - including malware from a browser or a malicious package script - can become root silently.

## Evidence

```text
/etc/sudoers: %wheel ALL=(ALL:ALL) NOPASSWD: ALL
```

## How to fix

Remove `NOPASSWD:` (edit with `sudo visudo`) or restrict it to specific, harmless commands.

Found by: [[2026-10-07 1456 testbox/System/Users & Access|Users & Access]]
