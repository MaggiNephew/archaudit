---
title: "L10 · System accounts with an interactive shell"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "L10"
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

# L10 · System accounts with an interactive shell

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!note] 🟦 Low — Users & Access
> Service accounts normally use `nologin`. A real shell makes a compromised service easier to turn into an interactive foothold.

## Evidence

```text
git (/bin/bash)
```

## How to fix

`sudo usermod -s /usr/bin/nologin <account>` unless the shell is required.

Found by: [[2026-10-07 1456 testbox/System/Users & Access|Users & Access]]
