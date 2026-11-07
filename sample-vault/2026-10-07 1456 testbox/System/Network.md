---
title: "Network"
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
---

# Network

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


_0 network service(s), firewall: none detected_

> [!danger] 3 finding(s) in this area
> - 🟧 **High** · [[2026-10-07 1456 testbox/Findings/H03 Redis (often unauthenticated) listening on all interfaces (port 6379)|H03 Redis (often unauthenticated) listening on all interfaces (port 6379)]]
> - 🟨 **Medium** · [[2026-10-07 1456 testbox/Findings/M05 No active firewall detected|M05 No active firewall detected]]
> - 🟨 **Medium** · [[2026-10-07 1456 testbox/Findings/M04 3 service socket(s) reachable from the network|M04 3 service socket(s) reachable from the network]]

> [!failure]- 3 item(s) not collected for Network
> - **Firewall rules (nftables ruleset)** — needs root: Re-run with `sudo archaudit`
> - **Process names for listening ports** — needs root: Re-run with `sudo archaudit`
> - **Effective sshd configuration** — needs root: Re-run with `sudo archaudit`

## Interfaces

| Interface | State | MAC | Addresses |
|---|---|---|---|
| lo | UNKNOWN | 00:00:00:00:00:00 | 127.0.0.1/8 |
| wlan0 | UP | 3c:a9:f4:12:34:56 | 192.168.1.42/24, fe80::1/64 |

## Routes

| Destination | Gateway | Device | Protocol |
|---|---|---|---|
| default | 192.168.1.1 | wlan0 | dhcp |
| 192.168.1.0/24 | — | wlan0 | kernel |

## Configuration

| Item | Value |
|---|---|
| DNS servers | none |
| Network services active | none detected |
| IPv4 forwarding | unknown |

## Firewall

| Item | Value |
|---|---|
| Firewall services active | none |
| nftables rules loaded | unknown (needs root) |

## Listening ports

| Proto | Address | Port | Reachable from | Process |
|---|---|---|---|---|
| tcp | 0.0.0.0 | 22 | all interfaces | sshd |
| tcp | :: | 22 | all interfaces | sshd |
| udp | 127.0.0.53 | 53 | localhost | ? |
| tcp | 127.0.0.1 | 631 | localhost | ? |
| tcp | 0.0.0.0 | 6379 | all interfaces | redis-server |
