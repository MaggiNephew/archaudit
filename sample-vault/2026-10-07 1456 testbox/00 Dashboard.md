---
title: "Security audit — testbox"
type: "dashboard"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
critical: 3
high: 7
medium: 10
low: 10
info: 1
not_collected: 3
ran_as_root: false
tags:
  - "archaudit"
  - "archaudit/dashboard"
  - "dashboard"
---

# Security audit — testbox

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 10 critical/high finding(s) need attention
> Start with the top of the table below.

> [!tip] Partial audit (not run as root)
> Some checks were skipped. Run `sudo archaudit` for full coverage — see [[2026-10-07 1456 testbox/02 Not Collected|Not Collected]].

## At a glance

|  | Severity | Count |
|---|---|---|
| 🟥 | Critical | 3 |
| 🟧 | High | 7 |
| 🟨 | Medium | 10 |
| 🟦 | Low | 10 |
| ⬜ | Info | 1 |

| Item | Value |
|---|---|
| Distribution | Arch Linux |
| Kernel | 6.10.1-arch1-1 |
| Last full upgrade | 2026-08-23 (45 days ago) |
| Pending updates | 2 |
| Vulnerable packages | 3 |
| Network-exposed ports | 2 |
| Root filesystem encrypted | no |
| Items not collected | 3 → [[2026-10-07 1456 testbox/02 Not Collected\|details]] |
| Ran as root | no |
| Options | defaults |
| Duration | 0s |
| archaudit version | 1.0.0 |

## Findings

| ID | Severity | Finding | Area |
|---|---|---|---|
| C01 | 🟥 Critical | [[2026-10-07 1456 testbox/Findings/C01 Vulnerable package- openssl\|Vulnerable package: openssl]] | Packages |
| C02 | 🟥 Critical | [[2026-10-07 1456 testbox/Findings/C02 Accounts with an empty password\|Accounts with an empty password]] | Users & Access |
| C03 | 🟥 Critical | [[2026-10-07 1456 testbox/Findings/C03 Additional accounts with UID 0 (root)\|Additional accounts with UID 0 (root)]] | Users & Access |
| H01 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H01 CPU mitigations disabled on the kernel command line\|CPU mitigations disabled on the kernel command line]] | Kernel & Boot |
| H02 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H02 CPU vulnerable to 1 side-channel issue(s)\|CPU vulnerable to 1 side-channel issue(s)]] | Kernel & Boot |
| H03 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H03 Redis (often unauthenticated) listening on all interfaces (port 6379)\|Redis (often unauthenticated) listening on all interfaces (port 6379)]] | Network |
| H04 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H04 SSH permits direct root login\|SSH permits direct root login]] | Network |
| H05 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H05 Vulnerable package- curl\|Vulnerable package: curl]] | Packages |
| H06 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H06 Weak package signature checking (myrepo- Never)\|Weak package signature checking (myrepo: Never)]] | Packages |
| H07 | 🟧 High | [[2026-10-07 1456 testbox/Findings/H07 Passwords stored with weak MD5 hashes\|Passwords stored with weak MD5 hashes]] | Users & Access |
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
| I01 | ⬜ Info | [[2026-10-07 1456 testbox/Findings/I01 1 AUR-foreign package(s) are outside security tracking\|1 AUR/foreign package(s) are outside security tracking]] | Packages |

## System notes

| Note | Summary | Findings |
|---|---|---|
| [[2026-10-07 1456 testbox/System/Overview\|Overview]] | Arch Linux on testbox, kernel 6.18.44-fc-v77 | 0 |
| [[2026-10-07 1456 testbox/System/Hardware\|Hardware]] | 12th Gen Intel(R) Core(TM) i7-1260P, 15.3 GiB RAM | 0 |
| [[2026-10-07 1456 testbox/System/Kernel & Boot\|Kernel & Boot]] | running 6.10.1-arch1-1 | 5 |
| [[2026-10-07 1456 testbox/System/Packages\|Packages]] | 4 installed, 1 AUR, 0 orphans | 7 |
| [[2026-10-07 1456 testbox/System/Vulnerable Packages\|Vulnerable Packages]] | 3 vulnerable, 2 with fix available | 3 |
| [[2026-10-07 1456 testbox/System/Network\|Network]] | 0 network service(s), firewall: none detected | 3 |
| [[2026-10-07 1456 testbox/System/SSH Server\|SSH Server]] | sshd running, root login: yes | 3 |
| [[2026-10-07 1456 testbox/System/Users & Access\|Users & Access]] | 2 user account(s), 1 in wheel | 7 |
| [[2026-10-07 1456 testbox/System/Services\|Services]] | 0 running, 0 failed, 0 enabled | 0 |
| [[2026-10-07 1456 testbox/System/Storage & Filesystems\|Storage & Filesystems]] | 1 disk(s), root encrypted: no | 2 |
| [[2026-10-07 1456 testbox/System/File Permissions\|File Permissions]] | 0 SUID/SGID files, 0 not on the known list | 0 |
| [[2026-10-07 1456 testbox/System/Logs\|Logs]] | 25 failed SSH login attempt(s) in 30 days | 1 |

## Dataview (optional)

With the Dataview community plugin, this live table lists open findings:

```dataview
TABLE severity, category, status
FROM "2026-10-07 1456 testbox/Findings"
SORT severity_rank DESC
```
