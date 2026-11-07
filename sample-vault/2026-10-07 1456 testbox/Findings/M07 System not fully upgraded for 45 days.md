---
title: "M07 · System not fully upgraded for 45 days"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "M07"
severity: "medium"
severity_rank: 3
category: "Packages"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/medium"
  - "category/packages"
---

# M07 · System not fully upgraded for 45 days

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!warning] 🟨 Medium — Packages
> Arch is a rolling release: security fixes arrive only through full upgrades. Partial upgrades are unsupported.

## Evidence

```text
last 'starting full system upgrade': 2026-08-23 14:56
```

## How to fix

Run `sudo pacman -Syu` (and update AUR packages) at least weekly.

## References

- <https://wiki.archlinux.org/title/System_maintenance>

Found by: [[2026-10-07 1456 testbox/System/Packages|Packages]]
