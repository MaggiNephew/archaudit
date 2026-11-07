---
title: "C03 · Additional accounts with UID 0 (root)"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "C03"
severity: "critical"
severity_rank: 5
category: "Users & Access"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/critical"
  - "category/users-access"
---

# C03 · Additional accounts with UID 0 (root)

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 🟥 Critical — Users & Access
> These accounts have full root privileges. A second UID-0 account is a classic backdoor technique.

## Evidence

```text
toor
```

## How to fix

Investigate immediately; remove or re-number the accounts.

Found by: [[2026-10-07 1456 testbox/System/Users & Access|Users & Access]]
