
# archaudit — Linux & Windows security audit → Obsidian vault

> **Read-only, for your own machines.** archaudit only reads files and runs query
> commands. It never installs, changes, or deletes anything on the system it audits.

## Overview

**What it does.** archaudit gathers as much information about a system as the current
privileges allow, checks it for known vulnerabilities and weak settings, and writes
everything as linked Markdown notes into `~/Documents/ArchAudit`, ready to open as an
Obsidian vault.

**Supported systems.**

| Platform | Package / update checks | Everything else |
|---|---|---|
| Arch and derivatives (EndeavourOS, Manjaro, CachyOS…) | pacman, `arch-audit` CVEs, `checkupdates` | full |
| Debian, Ubuntu, Mint, Kali, Pop!_OS… | apt/dpkg, security-suite updates, unattended-upgrades, `debsecan` (Debian) | full |
| Fedora, RHEL, Rocky, Alma… | dnf/rpm, security advisories, `gpgcheck`, dnf-automatic | full |
| Other Linux | not collected (reported as such) | generic Linux checks |
| Windows 10 / 11 | Windows Update, hotfixes, installed programs | firewall, Defender, BitLocker, UAC, services, event logs… |

Each run gets its own folder with:

- **00 Dashboard**: overall status, key facts, every finding and changes since the
  last scan of the same host.
- **01 Findings**: findings grouped by severity, with one note per finding containing
  evidence, a fix and references.
- **02 Not Collected**: everything the audit *could not* find out, why, and the exact
  command that fixes it (usually elevation or installing a tool). Missing data is never
  silently treated as "passed".
- **System/**: detailed inventory notes per area.
- **Raw/**: the raw output of the main commands.

**Assumptions.**

- Python 3.12 or newer.
- Linux: systemd is used (without it, service and journal checks become "not
  collected").
- Windows: Windows PowerShell 5.1 (built in to Windows 10/11).
- The audit runs locally on the machine being audited.

## Architecture

```
cli.py ── platform detection, target user, ~/Documents (XDG / Windows known folder)
  │
  ├─ platforms.py        OS + distro family (arch / debian / fedora / windows),
  │                      install and elevation hints
  ├─ Context (core.py)   every file read / command goes through here:
  │     • fixed argv, no shell, fixed PATH, minimal environment, timeouts
  │     • failures → Gap(item, reason, how-to-fix)   ← "Not Collected"
  │     • raw output kept for Raw/
  │
  ├─ collectors/  (Linux; run in order, one crash ≠ failed audit)
  │     system.py      overview, hardware, battery, NTP
  │     kernel.py      reboot-needed, cmdline, CPU vulns, microcode, LSM, Secure Boot, sysctl
  │     packages.py    dispatch + pacman backend   pkg_apt.py  pkg_dnf.py   _pkg.py (shared)
  │     network.py     interfaces, routes, DNS, listening ports, firewall, sshd
  │     users.py       accounts, UID 0, empty/weak passwords, sudo, privileged groups, homes
  │     services.py    running/failed/enabled units, legacy services, cron
  │     filesystem.py  lsblk, LUKS, disk usage, mount options, SUID/SGID, world-writable
  │     logs.py        journal errors, SSH brute force, sudo failures, coredumps
  │
  ├─ collectors/windows/  (fixed PowerShell scripts → JSON)
  │     system.py      version + support lifecycle, hardware
  │     security.py    Secure Boot, VBS/memory integrity, LSA protection, TPM, WDigest;
  │                    Defender / antivirus, exclusions, tamper protection
  │     updates.py     pending updates (security vs other), last install, reboot pending
  │     network.py     firewall profiles, listening ports, SMBv1, RDP/NLA, LLMNR/NetBIOS, sshd
  │     users.py       local accounts, admins, Guest/RID-500, UAC, auto-logon, AlwaysInstallElevated
  │     services.py    writable service/task binaries, unquoted paths, autostart
  │     storage.py     BitLocker / device encryption, disk usage, writable PATH folders
  │     logs.py        failed logons, RDP logons, log clearing, PowerShell logging
  │
  └─ writer.py   Obsidian vault: front matter, callouts, vault-relative wikilinks,
                 findings.json, "new since last scan", Audit History
```

**Libraries:** the Python standard library only.

**Optional tools for full coverage:**

```bash
sudo pacman -S --needed arch-audit pacman-contrib pciutils usbutils   # Arch
sudo apt install pciutils usbutils iproute2 debsecan                  # Debian (debsecan: Debian only)
sudo dnf install pciutils usbutils iproute                            # Fedora
```

## Security Considerations

- **Read-only by design.** No command writes to the system.
  - Arch: `checkupdates` uses a temporary copy of the sync database.
  - Debian: `apt-get -s` only *simulates* an upgrade against the lists already on disk.
  - Fedora: `dnf check-update` / `updateinfo` only query; `--offline` adds `-C`
    (cache only).
  - Windows: the Windows Update API is only searched. A test asserts that no
    state-changing cmdlet (`Set-`, `Remove-`, `Stop-`, `Enable-`…) appears in any script.
- **Network use.** Only CVE/update metadata lookups reach the network (`arch-audit`,
  `checkupdates`, `debsecan`, dnf metadata, Windows Update). `--offline` disables or
  restricts them to local caches.
- **Safe privilege handling.**
  - Linux under `sudo`: data is collected as root, then a forked child drops to the
    invoking user (`setgroups/setgid/setuid`) before writing anything.
  - Windows: an elevated run writes straight into the user's own profile.
  - Files are created with `O_EXCL|O_NOFOLLOW` (where the OS supports it), and a
    symlinked vault folder is refused.
- **No command injection.** Commands run as fixed argv lists. On Windows every check
  is a constant script passed with `-EncodedCommand`; nothing from the system or the
  user is interpolated into it. PowerShell is located only in the Windows system
  directories, so a planted `powershell.exe` elsewhere on `PATH` is never used.
- **The report is sensitive.** It maps your weaknesses.
  - Vault folders are `0700` and files `0600` on Linux.
  - Password hashes are never copied; only the hash *type* and locked/empty state. On
    Windows the auto-logon password is only reported as *present*, never read out.
  - The SSH, sudo and log notes contain usernames and IP addresses.
  - If Documents is synced by OneDrive, the default vault moves to `~/ArchAudit`.
  - Don't sync the vault to shared or public storage.

**Limitations.**

- CVE data covers official repository packages only (Arch tracker, Debian tracker via
  debsecan, Fedora/RHEL advisories). Ubuntu has no offline CVE matcher; pending updates
  from the `-security` pocket are reported instead. AUR, Flatpak, Snap, pip and most
  Windows third-party programs are listed but not matched against vulnerability data.
- Without root/administrator rights, these are recorded as "Not collected" rather than
  guessed: `/etc/shadow`, sudoers, the nftables ruleset, other users' processes,
  `sshd -T`, the full journal; on Windows the Security event log, BitLocker details,
  TPM and Defender exclusions.
- The Windows support table (`collectors/windows/system.py`) is static and must be
  updated when Microsoft ships a new feature update.
- The check list targets common misconfigurations. It is not a full CIS benchmark.

## Project Structure

```
archaudit/
├── pyproject.toml          packaging, `archaudit` command, ruff/mypy/pytest config
├── README.md
├── src/archaudit/
│   ├── __init__.py  __main__.py
│   ├── cli.py              arguments, platform, target user, privilege drop, exit codes
│   ├── core.py             Severity, Finding, Gap, Note, Runner, Context
│   ├── platforms.py        OS / distro family detection
│   ├── md.py               Obsidian Markdown helpers
│   ├── writer.py           vault writer, history, diff vs previous scan
│   └── collectors/         Linux collectors + package backends
│       └── windows/        Windows collectors (PowerShell)
└── tests/
    ├── conftest.py         fake filesystem root + scripted command runner
    ├── test_parsers.py     parsers (arch-audit, ss, sshd, sudoers, sysctl, Markdown…)
    ├── test_audit.py       simulated Arch system end-to-end, vault, diffing
    ├── test_platforms.py   detection, apt/dnf parsers, Ubuntu + Fedora end-to-end
    └── test_windows.py     Windows collectors against canned PowerShell JSON
```

## Quality gates

- `ruff check` (including the bandit `S` rules)
- `mypy --strict`, and `mypy --strict --platform win32`
- `pytest`: 85 tests
- Every embedded PowerShell script is parsed by PowerShell's own parser in development.

## Installation

**Linux — single file:**

```bash
python3 archaudit.pyz            # partial audit as your user
sudo python3 archaudit.pyz       # full audit; files still owned by you
```

**Linux — install as a command:**

```bash
pipx install ./archaudit
archaudit
sudo "$(command -v archaudit)"   # sudo's PATH doesn't include ~/.local/bin
```

**Windows:** install Python 3.12+ from python.org or `winget install Python.Python.3.12`,
then in PowerShell:

```powershell
py archaudit.pyz                 # partial audit as your user
# full audit: right-click Terminal → Run as administrator, then:
py archaudit.pyz
```

**Build the .pyz yourself:**

```bash
python -m zipapp src -m "archaudit.cli:main" -p "/usr/bin/env python3" -o archaudit.pyz
```

## Configuration

| Flag | Effect |
|---|---|
| `-o, --output DIR` | Vault folder. Default: `<Documents>/ArchAudit` of the invoking user (`~/ArchAudit` if Documents is OneDrive-synced). |
| `--offline` | Skip or cache-only the network checks. They are listed as not collected. |
| `--deep` | Package checksums (`pacman -Qkk` / `dpkg --verify` / `rpm -Va`) and a whole-filesystem SUID scan. Slower. |
| `--only AREA…` / `--skip AREA…` | Linux: `overview hardware kernel packages network users services filesystem logs`. Windows adds `defender`. |
| `--timeout SEC` | Per-command timeout. The default is 60. |
| `--log-level`, `--log-json` | Progress logging on stderr. |

Exit codes: `0` no critical/high findings · `1` critical/high findings present ·
`2` the report could not be written · `130` interrupted.

## Usage Examples

```bash
sudo archaudit                         # full audit → ~/Documents/ArchAudit
archaudit --offline                    # quick, no network, no sudo
sudo archaudit --deep                  # thorough (several minutes)
archaudit --only packages network      # just updates/CVEs and exposure
```

One vault can hold scans from several machines: each scan is compared only with the
previous scan of the same host, and `findings.json` records the platform.

**In Obsidian:** choose *Open folder as vault* and select the `ArchAudit` folder
itself (not a scan folder inside it; links are relative to the vault root).

## Security Review

1. **Trust in local tools.** If the system is already compromised, its tools can lie.
   archaudit is a hygiene tool, not a forensic or rootkit detector.
2. **Static check knowledge.** Known-SUID lists, risky ports, sysctl baselines and the
   Windows lifecycle table live in code and will age.
3. **Heuristic severities.** Adjust them to your threat model.
4. **Output format drift.** Text output (`arch-audit`, `apt-get -s`, `dnf`) is parsed
   defensively: if a tool prints output and none of it parses, the check is reported
   as failed — never as "0 vulnerable".
5. **Windows path not CI-tested on real Windows yet.** The collectors are tested
   against canned PowerShell output; run it on a real machine and report mismatches.

## Future Improvements

- CI on real Arch, Debian, Fedora containers and a Windows runner.
- AUR version checks against the AUR RPC (opt-in network check).
- winget-based third-party update checks on Windows.
- A "Remediation plan" note that orders fixes by effort and impact.
- Per-finding "accepted risk" notes that persist across runs.
