---
title: "L07 · 2 package update(s) pending"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "L07"
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

# L07 · 2 package update(s) pending

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!note] 🟦 Low — Packages
> Updates are available in the repositories. Security-relevant ones are listed separately under Vulnerable Packages. A kernel update is included (reboot afterwards).

## Evidence

```text
curl 8.1-1 -> 8.4.0-1
linux 6.11.0.arch1-1 -> 6.11.1.arch1-1
```

## How to fix

`sudo pacman -Syu`

Found by: [[2026-10-07 1456 testbox/System/Packages|Packages]]
