---
title: "Kernel & Boot"
type: "system"
host: "testbox"
scan: "2026-10-07 1456 testbox"
date: "2026-10-07 14:56"
category: "Kernel & Boot"
findings: 5
tags:
  - "archaudit"
  - "archaudit/system"
  - "kernel-boot"
  - "kernel"
  - "boot"
---

# Kernel & Boot

[[2026-10-07 1456 testbox/00 Dashboard|🏠 Dashboard]] · [[2026-10-07 1456 testbox/01 Findings|🛡 Findings]] · [[2026-10-07 1456 testbox/02 Not Collected|❓ Not collected]]


_running 6.10.1-arch1-1_

> [!danger] 5 finding(s) in this area
> - 🟧 **High** · [[2026-10-07 1456 testbox/Findings/H01 CPU mitigations disabled on the kernel command line|H01 CPU mitigations disabled on the kernel command line]]
> - 🟧 **High** · [[2026-10-07 1456 testbox/Findings/H02 CPU vulnerable to 1 side-channel issue(s)|H02 CPU vulnerable to 1 side-channel issue(s)]]
> - 🟨 **Medium** · [[2026-10-07 1456 testbox/Findings/M02 Kernel upgraded but system not rebooted|M02 Kernel upgraded but system not rebooted]]
> - 🟨 **Medium** · [[2026-10-07 1456 testbox/Findings/M01 CPU microcode package intel-ucode not installed|M01 CPU microcode package intel-ucode not installed]]
> - 🟦 **Low** · [[2026-10-07 1456 testbox/Findings/L03 1 kernel hardening setting(s) below recommendation|L03 1 kernel hardening setting(s) below recommendation]]

## Kernel

| Item | Value |
|---|---|
| Running release | 6.10.1-arch1-1 |
| Installed kernel packages | linux 6.11.0.arch1-1 |
| Module directories | 6.11.0-arch1-1 |
| Loaded modules | 0 |
| Taint flags | 0 (clean) |

## Command line

```text
root=/dev/sda2 rw mitigations=off quiet
```

## CPU vulnerability mitigations

|  | Issue | Kernel status |
|---|---|---|
| ✅ | mds | Mitigation: Clear CPU buffers |
| ✅ | meltdown | Not affected |
| ❌ | spectre_v2 | Vulnerable |

## Microcode

| Item | Value |
|---|---|
| CPU vendor | GenuineIntel |
| Microcode package | intel-ucode — MISSING |

## Security modules

| Item | Value |
|---|---|
| Active LSMs | unknown |
| Mandatory access control | none |
| Kernel lockdown | unknown |

## Boot

| Item | Value |
|---|---|
| Firmware | BIOS |
| Secure Boot | n/a (legacy BIOS) |
| Bootloader(s) detected | unknown |

## Kernel hardening (sysctl)

|  | Key | Current | Recommended | Purpose |
|---|---|---|---|---|
| ✅ | kernel.randomize_va_space | 2 | == 2 | full ASLR |
| ❌ | kernel.kptr_restrict | 0 | >= 1 | hide kernel pointers |
| ❔ | kernel.dmesg_restrict | unreadable/absent | == 1 | restrict kernel log to root |
| ✅ | kernel.unprivileged_bpf_disabled | 2 | >= 1 | block unprivileged eBPF (common LPE vector) |
| ❔ | kernel.yama.ptrace_scope | unreadable/absent | >= 1 | processes cannot ptrace non-children |
| ❔ | kernel.kexec_load_disabled | unreadable/absent | == 1 | prevent replacing the running kernel |
| ❔ | kernel.sysrq | unreadable/absent | == 0 | disable magic SysRq (physical access) |
| ✅ | fs.protected_symlinks | 1 | == 1 | symlink race protection |
| ❔ | fs.protected_hardlinks | unreadable/absent | == 1 | hardlink race protection |
| ❔ | fs.protected_fifos | unreadable/absent | >= 1 | FIFO race protection |
| ❔ | fs.protected_regular | unreadable/absent | >= 1 | regular-file race protection |
| ❔ | fs.suid_dumpable | unreadable/absent | == 0 | no core dumps from SUID programs |
| ❔ | net.ipv4.tcp_syncookies | unreadable/absent | == 1 | SYN flood protection |
| ❔ | net.ipv4.conf.all.rp_filter | unreadable/absent | >= 1 | reverse-path filtering |
| ❔ | net.ipv4.conf.all.accept_redirects | unreadable/absent | == 0 | ignore ICMP redirects |
| ❔ | net.ipv4.conf.all.send_redirects | unreadable/absent | == 0 | do not send ICMP redirects (not a router) |
| ❔ | net.ipv4.conf.all.accept_source_route | unreadable/absent | == 0 | drop source-routed packets |
| ❔ | net.ipv6.conf.all.accept_redirects | unreadable/absent | == 0 | ignore IPv6 redirects |
