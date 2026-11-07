---
title: "H01 · CPU mitigations disabled on the kernel command line"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "H01"
severity: "high"
severity_rank: 4
category: "Kernel & Boot"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/high"
  - "category/kernel-boot"
---

# H01 · CPU mitigations disabled on the kernel command line

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 🟧 High — Kernel & Boot
> `mitigations=off` turns off protections against Spectre, Meltdown, MDS, Retbleed and related CPU side-channel attacks.

## Evidence

```text
root=/dev/sda2 rw mitigations=off quiet
```

## How to fix

Remove `mitigations=off` from the bootloader configuration and regenerate it.

Found by: [[2026-10-07 1456 testbox/System/Kernel & Boot|Kernel & Boot]]
