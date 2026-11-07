---
title: "M02 · Kernel upgraded but system not rebooted"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "M02"
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

# M02 · Kernel upgraded but system not rebooted

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!warning] 🟨 Medium — Kernel & Boot
> The running kernel's modules are no longer installed. Security fixes in the new kernel are not active, and loading new modules will fail.

## Evidence

```text
running 6.10.1-arch1-1; installed module dirs: 6.11.0-arch1-1
```

## How to fix

Reboot to start the updated kernel.

Found by: [[2026-10-07 1456 testbox/System/Kernel & Boot|Kernel & Boot]]
