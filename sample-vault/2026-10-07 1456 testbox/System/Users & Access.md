---
title: "Users & Access"
type: "system"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
category: "Users & Access"
findings: 7
tags:
  - "archaudit"
  - "archaudit/system"
  - "users-access"
  - "users"
  - "access"
  - "sudo"
---

# Users & Access

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


_2 user account(s), 1 in wheel_

> [!danger] 7 finding(s) in this area
> - 🟥 **Critical** · [[2026-10-07 1456 testbox/Findings/C03 Additional accounts with UID 0 (root)|C03 Additional accounts with UID 0 (root)]]
> - 🟥 **Critical** · [[2026-10-07 1456 testbox/Findings/C02 Accounts with an empty password|C02 Accounts with an empty password]]
> - 🟧 **High** · [[2026-10-07 1456 testbox/Findings/H07 Passwords stored with weak MD5 hashes|H07 Passwords stored with weak MD5 hashes]]
> - 🟨 **Medium** · [[2026-10-07 1456 testbox/Findings/M09 Users in root-equivalent group 'docker'|M09 Users in root-equivalent group 'docker']]
> - 🟨 **Medium** · [[2026-10-07 1456 testbox/Findings/M10 sudo rules without password (NOPASSWD)|M10 sudo rules without password (NOPASSWD)]]
> - 🟦 **Low** · [[2026-10-07 1456 testbox/Findings/L10 System accounts with an interactive shell|L10 System accounts with an interactive shell]]
> - 🟦 **Low** · [[2026-10-07 1456 testbox/Findings/L09 Home directories readable by other users|L09 Home directories readable by other users]]

## Login-capable and human accounts

| User | UID | Shell | Home | Groups | Password |
|---|---|---|---|---|---|
| root | 0 | /bin/bash | /root | root | locked |
| toor | 0 | /bin/bash | /root | — | MD5 (weak) |
| git | 970 | /bin/bash | /var/lib/git | — | needs root |
| alice | 1000 | /bin/zsh | /home/alice | wheel | yescrypt |
| bob | 1001 | /bin/bash | /home/bob | docker | EMPTY |

> [!example]- All 6 accounts
> | User | UID | Shell |
> |---|---|---|
> | root | 0 | /bin/bash |
> | toor | 0 | /bin/bash |
> | bin | 1 | /usr/bin/nologin |
> | git | 970 | /bin/bash |
> | alice | 1000 | /bin/zsh |
> | bob | 1001 | /bin/bash |

## Privileged groups

| Group | Members | Grants |
|---|---|---|
| wheel | alice | can use sudo (if enabled in sudoers) |
| docker | bob | can start privileged containers = root without a password |
| libvirt | — | can manage VMs and host devices |
| disk | — | raw read/write access to disks |
| lxd | — | can start privileged containers |

## sudo rules

| File | Rule |
|---|---|
| /etc/sudoers | root ALL=(ALL:ALL) ALL |
| /etc/sudoers | %wheel ALL=(ALL:ALL) NOPASSWD: ALL |
| /etc/sudoers | @includedir /etc/sudoers.d |

## Home directory permissions

| User | Home | Mode |
|---|---|---|
| alice | /home/alice | drwxr-xr-x |

## Recent logins

```text
alice    tty1         Tue Oct  6 08:01   still logged in
```

## Password & lockout policy

| Item | Value |
|---|---|
| faillock deny after | 3 (default) |
