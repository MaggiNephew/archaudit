---
title: "M05 · No active firewall detected"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "M05"
severity: "medium"
severity_rank: 3
category: "Network"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/medium"
  - "category/network"
---

# M05 · No active firewall detected

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!warning] 🟨 Medium — Network
> No firewall service is running (ruleset could not be inspected without root). Any service listening on a network interface is reachable by other hosts on the same network, e.g. public Wi-Fi.

## How to fix

Enable a simple default-deny inbound firewall, e.g. `sudo pacman -S ufw && sudo ufw default deny incoming && sudo ufw enable && sudo systemctl enable --now ufw`, or use nftables/firewalld.

## References

- <https://wiki.archlinux.org/title/Uncomplicated_Firewall>
- <https://wiki.archlinux.org/title/Nftables>

Found by: [[2026-10-07 1456 testbox/System/Network|Network]]
