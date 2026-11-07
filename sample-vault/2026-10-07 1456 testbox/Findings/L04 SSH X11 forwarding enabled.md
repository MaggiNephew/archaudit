---
title: "L04 · SSH X11 forwarding enabled"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "L04"
severity: "low"
severity_rank: 2
category: "Network"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/low"
  - "category/network"
---

# L04 · SSH X11 forwarding enabled

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!note] 🟦 Low — Network
> X11 forwarding exposes the client's display to the server side.

## How to fix

Set `X11Forwarding no` unless you need it.

## References

- <https://wiki.archlinux.org/title/OpenSSH#Protection>

Found by: [[2026-10-07 1456 testbox/System/SSH Server|SSH Server]]
