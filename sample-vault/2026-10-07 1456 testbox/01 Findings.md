---
title: "Findings"
type: "index"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
tags:
  - "archaudit"
  - "archaudit/index"
  - "findings"
---

# Findings

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


## 🟥 Critical (3)

| ID | Severity | Finding | Area |
|---|---|---|---|
| C01 | 🟥 Critical | [[2026-10-07 1456 testbox/Findings/C01 Vulnerable package- openssl\|Vulnerable package: openssl]] | Packages |
| C02 | 🟥 Critical | [[2026-10-07 1456 testbox/Findings/C02 Accounts with an empty password\|Accounts with an empty password]] | Users & Access |
| C03 | 🟥 Critical | [[2026-10-07 1456 testbox/Findings/C03 Additional accounts with UID 0 (root)\|Additional accounts with UID 0 (root)]] | Users & Access |

## 🟧 High (7)

| ID | Severity | Finding | Area |
|---|---|---|---|
| H01 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H01 CPU mitigations disabled on the kernel command line\|CPU mitigations disabled on the kernel command line]] | Kernel & Boot |
| H02 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H02 CPU vulnerable to 1 side-channel issue(s)\|CPU vulnerable to 1 side-channel issue(s)]] | Kernel & Boot |
| H03 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H03 Redis (often unauthenticated) listening on all interfaces (port 6379)\|Redis (often unauthenticated) listening on all interfaces (port 6379)]] | Network |
| H04 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H04 SSH permits direct root login\|SSH permits direct root login]] | Network |
| H05 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H05 Vulnerable package- curl\|Vulnerable package: curl]] | Packages |
| H06 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H06 Weak package signature checking (myrepo- Never)\|Weak package signature checking (myrepo: Never)]] | Packages |
| H07 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H07 Passwords stored with weak MD5 hashes\|Passwords stored with weak MD5 hashes]] | Users & Access |

## 🟨 Medium (10)

| ID | Severity | Finding | Area |
|---|---|---|---|
| M01 | 🟨 Medium | [[2026-10-07 1456 testbox/Findings/M01 CPU microcode package intel-ucode not installed\|CPU microcode package intel-ucode not installed]] | Kernel & Boot |
| M02 | 🟨 Medium | [[2026-10-07 1456 testbox/Findings/M02 Kernel upgraded but system not rebooted\|Kernel upgraded but system not rebooted]] | Kernel & Boot |
| M03 | 🟨 Medium | [[2026-10-07 1456 testbox/Findings/M03 SSH brute-force activity- 25 failed logins in 30 days\|SSH brute-force activity: 25 failed logins in 30 days]] | Logs |
| M04 | 🟨 Medium | [[2026-10-07 1456 testbox/Findings/M04 3 service socket(s) reachable from the network\|3 service socket(s) reachable from the network]] | Network |
| M05 | 🟨 Medium | [[2026-10-07 1456 testbox/Findings/M05 No active firewall detected\|No active firewall detected]] | Network |
| M06 | 🟨 Medium | [[2026-10-07 1456 testbox/Findings/M06 SSH accepts password logins\|SSH accepts password logins]] | Network |
| M07 | 🟨 Medium | [[2026-10-07 1456 testbox/Findings/M07 System not fully upgraded for 45 days\|System not fully upgraded for 45 days]] | Packages |
| M08 | 🟨 Medium | [[2026-10-07 1456 testbox/Findings/M08 Vulnerable package- libxml2\|Vulnerable package: libxml2]] | Packages |
| M09 | 🟨 Medium | [[2026-10-07 1456 testbox/Findings/M09 Users in root-equivalent group 'docker'\|Users in root-equivalent group 'docker']] | Users & Access |
| M10 | 🟨 Medium | [[2026-10-07 1456 testbox/Findings/M10 sudo rules without password (NOPASSWD)\|sudo rules without password (NOPASSWD)]] | Users & Access |

## 🟦 Low (10)

| ID | Severity | Finding | Area |
|---|---|---|---|
| L01 | 🟦 Low | [[2026-10-07 1456 testbox/Findings/L01 Root filesystem is not encrypted\|Root filesystem is not encrypted]] | Filesystem |
| L02 | 🟦 Low | [[2026-10-07 1456 testbox/Findings/L02 Temporary-shared mounts lack hardening options\|Temporary/shared mounts lack hardening options]] | Filesystem |
| L03 | 🟦 Low | [[2026-10-07 1456 testbox/Findings/L03 1 kernel hardening setting(s) below recommendation\|1 kernel hardening setting(s) below recommendation]] | Kernel & Boot |
| L04 | 🟦 Low | [[2026-10-07 1456 testbox/Findings/L04 SSH X11 forwarding enabled\|SSH X11 forwarding enabled]] | Network |
| L05 | 🟦 Low | [[2026-10-07 1456 testbox/Findings/L05 1 file(s) from installed packages are missing\|1 file(s) from installed packages are missing]] | Packages |
| L06 | 🟦 Low | [[2026-10-07 1456 testbox/Findings/L06 1 mirror(s) use plain HTTP\|1 mirror(s) use plain HTTP]] | Packages |
| L07 | 🟦 Low | [[2026-10-07 1456 testbox/Findings/L07 2 package update(s) pending\|2 package update(s) pending]] | Packages |
| L08 | 🟦 Low | [[2026-10-07 1456 testbox/Findings/L08 Packages are excluded from upgrades\|Packages are excluded from upgrades]] | Packages |
| L09 | 🟦 Low | [[2026-10-07 1456 testbox/Findings/L09 Home directories readable by other users\|Home directories readable by other users]] | Users & Access |
| L10 | 🟦 Low | [[2026-10-07 1456 testbox/Findings/L10 System accounts with an interactive shell\|System accounts with an interactive shell]] | Users & Access |

## ⬜ Info (1)

| ID | Severity | Finding | Area |
|---|---|---|---|
| I01 | ⬜ Info | [[2026-10-07 1456 testbox/Findings/I01 1 AUR-foreign package(s) are outside security tracking\|1 AUR/foreign package(s) are outside security tracking]] | Packages |

## By area

| Area | Findings |
|---|---|
| Packages | 10 |
| Users & Access | 7 |
| Network | 6 |
| Kernel & Boot | 5 |
| Filesystem | 2 |
| Logs | 1 |
