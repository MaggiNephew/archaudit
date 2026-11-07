---
title: "Not Collected"
type: "gaps"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
count: 3
tags:
  - "archaudit"
  - "archaudit/gaps"
  - "gaps"
---

# Not Collected

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


Everything the audit tried to gather but could not, why, and how to get it next time. Missing data is **not** the same as a passing check.

> [!tip] Get full coverage
> - Run the audit with `sudo` to cover root-only items.

## Needs root (3)

| Item | Area | Detail | How to fix |
|---|---|---|---|
| Firewall rules (nftables ruleset) | Network | `nft list ruleset` requires root | Re-run with `sudo archaudit` |
| Process names for listening ports | Network | ss only shows processes owned by the current user | Re-run with `sudo archaudit` |
| Effective sshd configuration | Network | parsed config files instead of `sshd -T` (Match blocks ignored) | Re-run with `sudo archaudit` |
