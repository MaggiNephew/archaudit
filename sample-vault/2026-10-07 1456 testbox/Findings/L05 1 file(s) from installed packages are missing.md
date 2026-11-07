---
title: "L05 · 1 file(s) from installed packages are missing"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "L05"
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

# L05 · 1 file(s) from installed packages are missing

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!note] 🟦 Low — Packages
> Files owned by packages have been deleted. Often harmless (cleaned docs/locales) but can indicate tampering or a broken install.

## Evidence

```text
warning: curl: /usr/share/doc/curl/README (No such file or directory)
```

## How to fix

Reinstall affected packages: `sudo pacman -S <pkg>`.

Found by: [[2026-10-07 1456 testbox/System/Packages|Packages]]
