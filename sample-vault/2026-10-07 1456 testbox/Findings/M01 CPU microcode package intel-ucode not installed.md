---
title: "M01 · CPU microcode package intel-ucode not installed"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "M01"
severity: "medium"
severity_rank: 3
category: "Kernel & Boot"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/medium"
  - "category/kernel-boot"
---

# M01 · CPU microcode package intel-ucode not installed

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!warning] 🟨 Medium — Kernel & Boot
> Microcode updates fix CPU bugs and are required for several Spectre-class mitigations. Without the package, only the (often outdated) firmware microcode is used.

## How to fix

`sudo pacman -S intel-ucode`, then make sure your bootloader loads it (mkinitcpio `microcode` hook or an initrd entry) and reboot.

## References

- <https://wiki.archlinux.org/title/Microcode>

Found by: [[2026-10-07 1456 testbox/System/Kernel & Boot|Kernel & Boot]]
