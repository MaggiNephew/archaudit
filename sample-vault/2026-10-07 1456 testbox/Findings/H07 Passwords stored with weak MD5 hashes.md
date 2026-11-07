---
title: "H07 · Passwords stored with weak MD5 hashes"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "H07"
severity: "high"
severity_rank: 4
category: "Users & Access"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/high"
  - "category/users-access"
---

# H07 · Passwords stored with weak MD5 hashes

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 🟧 High — Users & Access
> MD5-crypt hashes can be cracked quickly if `/etc/shadow` leaks.

## Evidence

```text
toor
```

## How to fix

Have the users change their passwords; Arch defaults to yescrypt.

Found by: [[2026-10-07 1456 testbox/System/Users & Access|Users & Access]]
