---
title: "L03 · 1 kernel hardening setting(s) below recommendation"
type: "finding"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
id: "L03"
severity: "low"
severity_rank: 2
category: "Kernel & Boot"
status: "open"
tags:
  - "archaudit"
  - "archaudit/finding"
  - "severity/low"
  - "category/kernel-boot"
---

# L03 · 1 kernel hardening setting(s) below recommendation

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


> [!note] 🟦 Low — Kernel & Boot
> These sysctl values are weaker than common hardening baselines (KSPP, CIS).

## Evidence

```text
kernel.kptr_restrict = 0 (want >= 1)
```

## How to fix

Review, then persist the values in `/etc/sysctl.d/99-hardening.conf` and run `sudo sysctl --system`:

```ini
kernel.kptr_restrict = 1
```

## References

- <https://wiki.archlinux.org/title/Security#Kernel_hardening>

Found by: [[2026-10-07 1456 testbox/System/Kernel & Boot|Kernel & Boot]]
