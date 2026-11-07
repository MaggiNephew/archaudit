---
title: "C02 · Accounts with an empty password"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "C02"
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

# C02 · Accounts with an empty password

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 🟥 Critical — Users & Access
> These accounts can log in without any password.

## Evidence

```text
bob
```

## How to fix

Set a password (`sudo passwd <user>`) or lock the account (`sudo passwd -l <user>`).

Found by: [[2026-10-07 1456 testbox/System/Users & Access|Users & Access]]
