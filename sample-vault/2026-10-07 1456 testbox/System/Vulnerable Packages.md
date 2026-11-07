---
title: "Vulnerable Packages"
type: "system"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
category: "Packages"
findings: 3
tags:
  - "archaudit"
  - "archaudit/system"
  - "packages"
  - "packages"
  - "vulnerabilities"
  - "cve"
---

# Vulnerable Packages

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


_3 vulnerable, 2 with fix available_

> [!danger] 3 finding(s) in this area
> - 🟥 **Critical** · [[2026-10-07 1456 testbox/Findings/C01 Vulnerable package- openssl|C01 Vulnerable package: openssl]]
> - 🟧 **High** · [[2026-10-07 1456 testbox/Findings/H05 Vulnerable package- curl|H05 Vulnerable package: curl]]
> - 🟨 **Medium** · [[2026-10-07 1456 testbox/Findings/M08 Vulnerable package- libxml2|M08 Vulnerable package: libxml2]]

> [!abstract] Source
> Installed package versions matched against the [Arch Security Tracker](https://security.archlinux.org) by `arch-audit`.

## Affected packages

| Risk | Package | Fixed in | Issues |
|---|---|---|---|
| 🟥 Critical | openssl | 3.3.2-1 (testing) | CVE-2024-9999 |
| 🟧 High | curl | 8.4.0-1 | CVE-2023-38545, CVE-2023-38546 |
| 🟨 Medium | libxml2 | no fix yet | CVE-2024-0001 |
