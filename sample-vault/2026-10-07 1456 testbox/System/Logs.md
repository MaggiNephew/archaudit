---
title: "Logs"
type: "system"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
category: "Logs"
findings: 1
tags:
  - "archaudit"
  - "archaudit/system"
  - "logs"
  - "logs"
  - "journal"
---

# Logs

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


_25 failed SSH login attempt(s) in 30 days_

> [!warning] 1 finding(s) in this area
> - 🟨 **Medium** · [[2026-10-07 1456 testbox/Findings/M03 SSH brute-force activity- 25 failed logins in 30 days|M03 SSH brute-force activity: 25 failed logins in 30 days]]

## Errors this boot (0 shown, max 200)

> [!example]- journalctl -b -p err
> ```text
> (empty)
> ```

## SSH authentication (last 30 days)

| Item | Value |
|---|---|
| Failed attempts | 25 |
| Distinct source IPs | 3 |
| Successful logins | 1 |

| Source IP | Failures |
|---|---|
| 203.0.113.0 | 9 |
| 203.0.113.1 | 8 |
| 203.0.113.2 | 8 |

| User | From | Method |
|---|---|---|
| alice | 192.0.2.5 | publickey |

## Logging setup

| Item | Value |
|---|---|
| Linux audit daemon (auditd) | not running |
