---
title: "M04 · 3 service socket(s) reachable from the network"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "M04"
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

# M04 · 3 service socket(s) reachable from the network

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!warning] 🟨 Medium — Network
> These sockets listen on non-loopback addresses. Each is attack surface; no firewall was detected to filter them.

## Evidence

```text
tcp 0.0.0.0:22 sshd
tcp :::22 sshd
tcp 0.0.0.0:6379 redis-server
```

## How to fix

Stop services you don't need (`systemctl disable --now <unit>`), bind local-only services to 127.0.0.1, and filter the rest with a firewall.

Found by: [[2026-10-07 1456 testbox/System/Network|Network]]
