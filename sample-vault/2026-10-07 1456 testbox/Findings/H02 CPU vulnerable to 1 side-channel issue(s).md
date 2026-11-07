---
title: "H02 · CPU vulnerable to 1 side-channel issue(s)"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "H02"
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

# H02 · CPU vulnerable to 1 side-channel issue(s)

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!danger] 🟧 High — Kernel & Boot
> The kernel reports these CPU vulnerabilities as unmitigated. Some can only be fixed with a microcode update; some require disabling SMT.

## Evidence

```text
spectre_v2: Vulnerable
```

## How to fix

Install the CPU microcode package (`intel-ucode` or `amd-ucode`), keep the kernel and firmware (BIOS/UEFI) updated, and do not boot with mitigations off.

## References

- <https://docs.kernel.org/admin-guide/hw-vuln/index.html>

Found by: [[2026-10-07 1456 testbox/System/Kernel & Boot|Kernel & Boot]]
