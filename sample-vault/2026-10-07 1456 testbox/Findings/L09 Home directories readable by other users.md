---
title: "L09 · Home directories readable by other users"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "L09"
severity: "low"
severity_rank: 2
category: "Users & Access"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/low"
  - "category/users-access"
---

# L09 · Home directories readable by other users

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!note] 🟦 Low — Users & Access
> Other local accounts and services can list or read these home directories.

## Evidence

```text
/home/alice drwxr-xr-x
```

## How to fix

`chmod 700 /home/<user>`

Found by: [[2026-10-07 1456 testbox/System/Users & Access|Users & Access]]
