---
title: "C01 · Vulnerable package: openssl"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "C01"
severity: "critical"
severity_rank: 5
category: "Packages"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/critical"
  - "category/packages"
---

# C01 · Vulnerable package: openssl

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 🟥 Critical — Packages
> `openssl` has known security issues: CVE-2024-9999.

## Evidence

```text
CVE-2024-9999
```

## How to fix

Update now: `sudo pacman -Syu` (fixed in **3.3.2-1**, currently only in the testing repos).

## References

- <https://security.archlinux.org/package/openssl>
- <https://security.archlinux.org/CVE-2024-9999>

Found by: [[2026-10-07 1456 testbox/System/Vulnerable Packages|Vulnerable Packages]]
