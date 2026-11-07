---
title: "Packages"
type: "system"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
category: "Packages"
findings: 7
tags:
  - "archaudit"
  - "archaudit/system"
  - "packages"
  - "packages"
  - "pacman"
---

# Packages

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


_4 installed, 1 AUR, 0 orphans_

> [!danger] 7 finding(s) in this area
> - 🟧 **High** · [[2026-10-07 1456 testbox/Findings/H06 Weak package signature checking (myrepo- Never)|H06 Weak package signature checking (myrepo: Never)]]
> - 🟨 **Medium** · [[2026-10-07 1456 testbox/Findings/M07 System not fully upgraded for 45 days|M07 System not fully upgraded for 45 days]]
> - 🟦 **Low** · [[2026-10-07 1456 testbox/Findings/L07 2 package update(s) pending|L07 2 package update(s) pending]]
> - 🟦 **Low** · [[2026-10-07 1456 testbox/Findings/L08 Packages are excluded from upgrades|L08 Packages are excluded from upgrades]]
> - 🟦 **Low** · [[2026-10-07 1456 testbox/Findings/L06 1 mirror(s) use plain HTTP|L06 1 mirror(s) use plain HTTP]]
> - 🟦 **Low** · [[2026-10-07 1456 testbox/Findings/L05 1 file(s) from installed packages are missing|L05 1 file(s) from installed packages are missing]]
> - ⬜ **Info** · [[2026-10-07 1456 testbox/Findings/I01 1 AUR-foreign package(s) are outside security tracking|I01 1 AUR/foreign package(s) are outside security tracking]]

## Summary

| Item | Value |
|---|---|
| Installed packages | 4 |
| Explicitly installed | 3 |
| Foreign / AUR packages | 1 |
| Orphans (unneeded dependencies) | 0 |
| AUR helpers present | none |

> [!info] Related
> See [[2026-10-07 1456 testbox/System/Vulnerable Packages|Vulnerable Packages]] for CVEs.

## Updates

| Item | Value |
|---|---|
| Last full upgrade (pacman -Syu) | 2026-08-23 (45 days ago) |

## Pending updates

| Package | Installed | Available |
|---|---|---|
| curl | 8.1-1 | 8.4.0-1 |
| linux | 6.11.0.arch1-1 | 6.11.1.arch1-1 |

## pacman configuration

| Item | Value |
|---|---|
| Enabled repositories | core, myrepo |
| Testing repos | none |
| IgnorePkg / IgnoreGroup | linux |

| Section | SigLevel |
|---|---|
| options | Required DatabaseOptional |
| myrepo | Never |

| Item | Value |
|---|---|
| Active mirrors | 2 |
| Plain-HTTP mirrors | 1 |

## Package file integrity

| Item | Value |
|---|---|
| Check | pacman -Qk |
| Missing files | 1 |
| Modified files (outside /etc) | not checked (use --deep) |

## Foreign / AUR packages

| Package | Version |
|---|---|
| yay-bin | 12.0-1 |

## Explicitly installed packages

> [!example]- 3 packages
> | Package | Version |
> |---|---|
> | curl | 8.1-1 |
> | linux | 6.11.0.arch1-1 |
> | yay-bin | 12.0-1 |
