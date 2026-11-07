---
title: "H03 · Redis (often unauthenticated) listening on all interfaces (port 6379)"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "H03"
severity: "high"
severity_rank: 4
category: "Network"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/high"
  - "category/network"
---

# H03 · Redis (often unauthenticated) listening on all interfaces (port 6379)

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 🟧 High — Network
> Redis (often unauthenticated) is reachable from the network on 0.0.0.0:6379 by redis-server.

## Evidence

```text
tcp 0.0.0.0:6379 redis-server
```

## How to fix

Bind it to 127.0.0.1 if only local use is needed, require authentication/TLS, or block the port in the firewall. Disable the service if unused.

Found by: [[2026-10-07 1456 testbox/System/Network|Network]]
