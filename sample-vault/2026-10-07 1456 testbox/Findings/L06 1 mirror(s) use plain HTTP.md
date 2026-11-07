---
title: "L06 · 1 mirror(s) use plain HTTP"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "L06"
severity: "low"
severity_rank: 2
category: "Packages"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/low"
  - "category/packages"
---

# L06 · 1 mirror(s) use plain HTTP

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!note] 🟦 Low — Packages
> Packages are signature-checked, but HTTP lets an attacker on the network see what you install and attempt stale-metadata (freeze) attacks.

## Evidence

```text
http://mirror.example/$repo/os/$arch
```

## How to fix

Use HTTPS mirrors only, e.g. `reflector --protocol https ...`.

Found by: [[2026-10-07 1456 testbox/System/Packages|Packages]]
