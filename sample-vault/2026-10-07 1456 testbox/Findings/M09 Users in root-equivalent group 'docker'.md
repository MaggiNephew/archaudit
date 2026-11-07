---
title: "M09 · Users in root-equivalent group 'docker'"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "M09"
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

# M09 · Users in root-equivalent group 'docker'

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!warning] 🟨 Medium — Users & Access
> Members of `docker` can start privileged containers = root without a password.

## Evidence

```text
bob
```

## How to fix

Remove users who don't need it: `sudo gpasswd -d <user> docker`. For Docker consider rootless mode or podman.

Found by: [[2026-10-07 1456 testbox/System/Users & Access|Users & Access]]
