---
title: "H06 · Weak package signature checking (myrepo: Never)"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "H06"
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

# H06 · Weak package signature checking (myrepo: Never)

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 🟧 High — Packages
> pacman will install packages whose signatures are missing or not verified, allowing a malicious mirror or MITM to supply packages.

## Evidence

```text
[myrepo] SigLevel = Never
```

## How to fix

Use the default `SigLevel = Required DatabaseOptional` in `/etc/pacman.conf` and fix keyring problems with `sudo pacman -S archlinux-keyring` instead.

## References

- <https://wiki.archlinux.org/title/Pacman/Package_signing>

Found by: [[2026-10-07 1456 testbox/System/Packages|Packages]]
