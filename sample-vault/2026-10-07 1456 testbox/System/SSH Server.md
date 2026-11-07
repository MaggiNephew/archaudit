---
title: "SSH Server"
type: "system"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
category: "Network"
findings: 3
tags:
  - "archaudit"
  - "archaudit/system"
  - "network"
  - "network"
  - "ssh"
---

# SSH Server

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


_sshd running, root login: yes_

> [!danger] 3 finding(s) in this area
> - 🟧 **High** · [[2026-10-07 1456 testbox/Findings/H04 SSH permits direct root login|H04 SSH permits direct root login]]
> - 🟨 **Medium** · [[2026-10-07 1456 testbox/Findings/M06 SSH accepts password logins|M06 SSH accepts password logins]]
> - 🟦 **Low** · [[2026-10-07 1456 testbox/Findings/L04 SSH X11 forwarding enabled|L04 SSH X11 forwarding enabled]]

> [!failure]- 3 item(s) not collected for Network
> - **Firewall rules (nftables ruleset)** — needs root: Re-run with `sudo archaudit`
> - **Process names for listening ports** — needs root: Re-run with `sudo archaudit`
> - **Effective sshd configuration** — needs root: Re-run with `sudo archaudit`

| Item | Value |
|---|---|
| Service state | active |
| Enabled at boot | enabled |
| Settings source | sshd_config files |

## Settings

| Item | Value |
|---|---|
| Port | 22 |
| PermitRootLogin | yes |
| PasswordAuthentication | no |
| KbdInteractiveAuthentication | yes |
| PermitEmptyPasswords | no |
| PubkeyAuthentication | yes |
| X11Forwarding | yes |
| MaxAuthTries | 6 |
