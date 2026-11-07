---
title: "H05 · Vulnerable package: curl"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "H05"
severity: "high"
severity_rank: 4
category: "Packages"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/high"
  - "category/packages"
---

# H05 · Vulnerable package: curl

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 🟧 High — Packages
> `curl` has known security issues: CVE-2023-38545, CVE-2023-38546.

## Evidence

```text
CVE-2023-38545, CVE-2023-38546
```

## How to fix

Update now: `sudo pacman -Syu` (fixed in **8.4.0-1**).

## References

- <https://security.archlinux.org/package/curl>
- <https://security.archlinux.org/CVE-2023-38545>
- <https://security.archlinux.org/CVE-2023-38546>

Found by: [[2026-10-07 1456 testbox/System/Vulnerable Packages|Vulnerable Packages]]
