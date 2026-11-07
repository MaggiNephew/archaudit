---
title: "I01 · 1 AUR/foreign package(s) are outside security tracking"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "I01"
severity: "info"
severity_rank: 1
category: "Packages"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/info"
  - "category/packages"
---

# I01 · 1 AUR/foreign package(s) are outside security tracking

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!info] ⬜ Info — Packages
> Packages not from the official repositories are not covered by the Arch Security Tracker or `arch-audit`, and are not signed by Arch developers. You must track their updates and review their PKGBUILDs yourself.

## Evidence

```text
yay-bin 12.0-1
```

## How to fix

Update them regularly with your AUR helper; remove ones you no longer use.

Found by: [[2026-10-07 1456 testbox/System/Packages|Packages]]
