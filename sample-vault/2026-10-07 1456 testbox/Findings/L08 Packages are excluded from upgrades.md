---
title: "L08 · Packages are excluded from upgrades"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "L08"
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

# L08 · Packages are excluded from upgrades

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!note] 🟦 Low — Packages
> IgnorePkg/IgnoreGroup hold packages back, so they miss security fixes and can cause partial-upgrade breakage.

## Evidence

```text
linux
```

## How to fix

Remove the entries from `/etc/pacman.conf` once the reason is resolved.

Found by: [[2026-10-07 1456 testbox/System/Packages|Packages]]
