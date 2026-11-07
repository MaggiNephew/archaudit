---
title: "M03 · SSH brute-force activity: 25 failed logins in 30 days"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "M03"
severity: "medium"
severity_rank: 3
category: "Logs"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/medium"
  - "category/logs"
---

# M03 · SSH brute-force activity: 25 failed logins in 30 days

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!warning] 🟨 Medium — Logs
> 3 source address(es) tried to log in; most-targeted usernames: admin.

## Evidence

```text
203.0.113.0: 9
203.0.113.1: 8
203.0.113.2: 8
```

## How to fix

Disable password authentication, restrict `AllowUsers`, and add `sshguard` or `fail2ban`; avoid exposing SSH to the internet if not required.

Found by: [[2026-10-07 1456 testbox/System/Logs|Logs]]
