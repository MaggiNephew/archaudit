
# archaudit — Arch Linux security audit → Obsidian vault

> **Read-only, for your own machines.** archaudit only reads files and runs query
> commands. It never installs, changes, or deletes anything on the system it audits.

## Overview

**What it does.** archaudit gathers as much information about an Arch Linux system as
the current privileges allow, checks it for known vulnerabilities and weak settings,
and writes everything as linked Markdown notes into `~/Documents/ArchAudit`, ready to
open as an Obsidian vault.

Each run gets its own folder with:

- **00 Dashboard**: overall status, key facts, every finding and changes since the
  last scan.
- **01 Findings**: findings grouped by severity, with one note per finding containing
  evidence, a fix and references.
- **02 Not Collected**: everything the audit *could not* find out, why, and the exact
  command that fixes it (usually `sudo` or installing a tool). Missing data is never
  silently treated as "passed".
- **System/**: detailed inventory notes for hardware, kernel and boot, packages, CVEs,
  network, SSH, users, services, storage, file permissions and logs.
- **Raw/**: the raw output of the main commands.

**Problem it solves.** On a rolling-release desktop or server, it's hard to answer three
questions:

- Am I running vulnerable packages?
- What is exposed to the network?
- What did I misconfigure?

The answers are spread over `arch-audit`, `pacman.log`, `/proc/sys`, `sshd_config`,
`ss`, `/etc/shadow` and the journal. archaudit collects them into one browsable,
searchable, diffable place.

**Assumptions.**

- Arch Linux or an Arch derivative (EndeavourOS, Manjaro, CachyOS). On other distros it
  still runs, but package checks become "not collected".
- systemd is used.
- Python 3.12 or newer is installed (`sudo pacman -S python`).
- The audit runs locally on the machine being audited.

## Architecture

```
cli.py ── target user + ~/Documents (XDG aware)
  │
  ├─ Context (core.py)   every file read / command goes through here:
  │     • fixed argv, no shell, C locale, timeouts
  │     • failures → Gap(item, reason, how-to-fix)   ← "Not Collected"
  │     • raw output kept for Raw/
  │
  ├─ collectors/ (run in order, one crash ≠ failed audit)
  │     system.py     overview, hardware, battery, NTP
  │     kernel.py     reboot-needed, cmdline, CPU vulns, microcode, LSM, Secure Boot, sysctl
  │     packages.py   arch-audit CVEs, checkupdates, last -Syu, pacman.conf, mirrors, integrity
  │     network.py    interfaces, routes, DNS, listening ports, firewall, sshd
  │     users.py      accounts, UID 0, empty/weak passwords, sudo, privileged groups, homes
  │     services.py   running/failed/enabled units, legacy services, cron
  │     filesystem.py lsblk, LUKS, disk usage, mount options, SUID/SGID, world-writable
  │     logs.py       journal errors, SSH brute force, sudo failures, coredumps
  │
  └─ writer.py   Obsidian vault: front matter, callouts, vault-relative wikilinks,
                 findings.json, "new since last scan", Audit History
```

**Libraries:** the Python standard library only.

**Optional tools for full coverage:**

```bash
sudo pacman -S --needed arch-audit pacman-contrib pciutils usbutils
```

## Security Considerations

- **Read-only by design.** No command writes to the system. `checkupdates` uses a
  temporary copy of the sync database instead of the real one, so it never causes a
  partial upgrade.
- **Network use.** Only `arch-audit` and `checkupdates` reach the network: they
  download tracker data and package databases from Arch servers. `--offline` disables
  both.
- **Safe privilege handling under `sudo`.**
  - Data is collected as root.
  - A forked child then drops to the invoking user (`setgroups/setgid/setuid`) before
    writing anything, so root never writes into a user-controlled path.
  - Files are created with `O_EXCL|O_NOFOLLOW`, and a symlinked vault folder is
    refused. Both are tested.
- **The report is sensitive.** It maps your weaknesses, so the vault folders are
  `0700` and the files `0600`.
  - Password hashes are never copied into the report; only the hash *type* and
    locked/empty state appear.
  - The SSH, sudo and log notes do contain usernames and IP addresses.
  - Don't sync the vault to shared or public storage.
- **No shell execution.** Commands run as fixed argv lists with a minimal `PATH` and
  `LC_ALL=C`, and every command has a timeout.

**Limitations.**

- The CVE data covers official repository packages only. AUR, Flatpak and pip packages
  are listed but not matched against vulnerability data.
- Without root, these are recorded as "Not collected" rather than guessed:
  `/etc/shadow`, sudoers, the nftables ruleset, other users' processes, `sshd -T` and
  the full journal.
- sshd settings parsed from the config files (non-root) ignore `Match` blocks.
- The default SUID scan covers the usual locations; `--deep` scans the whole root
  filesystem.
- The check list targets common misconfigurations. It is not a full CIS benchmark.

## Project Structure

```
archaudit/
├── pyproject.toml          packaging, `archaudit` command, ruff/mypy/pytest config
├── README.md
├── src/archaudit/
│   ├── __init__.py  __main__.py
│   ├── cli.py              arguments, target user, privilege drop, exit codes
│   ├── core.py             Severity, Finding, Gap, Note, Runner, Context
│   ├── md.py               Obsidian Markdown helpers (tables, callouts, front matter)
│   ├── writer.py           vault writer, history, diff vs previous scan
│   └── collectors/         system, kernel, packages, network, users,
│                           services, filesystem, logs, _util
└── tests/                  30 tests: parsers + simulated Arch system end-to-end
    ├── conftest.py         fake filesystem root + scripted command runner
    ├── test_parsers.py
    └── test_audit.py       incl. "every wikilink resolves" and "no hashes leak"
```

## Source Code

See `src/archaudit/`. Each module starts with a docstring explaining its design.
Quality gates passing at release:

- `ruff check` (including the bandit `S` rules)
- `mypy --strict`
- `pytest`: 30 passed

## Installation

**Option A — single file (simplest):**

```bash
sudo pacman -S --needed python arch-audit pacman-contrib pciutils usbutils
python archaudit.pyz            # partial audit as your user
sudo python archaudit.pyz       # full audit; files still owned by you
```

**Option B — install as a command:**

```bash
sudo pacman -S --needed python-pipx
pipx install ./archaudit
archaudit
sudo "$(command -v archaudit)"  # sudo's PATH doesn't include ~/.local/bin
```

**Build the .pyz yourself:**

```bash
python -m zipapp src -m "archaudit.cli:main" -p "/usr/bin/env python3" -o archaudit.pyz
```

## Configuration

No config file is needed. Behaviour is controlled with flags:

| Flag | Effect |
|---|---|
| `-o, --output DIR` | Vault folder. The default is `<XDG Documents>/ArchAudit` of the invoking user. |
| `--offline` | Skip the network checks (`arch-audit`, `checkupdates`). They are listed as not collected. |
| `--deep` | Run `pacman -Qkk` (checksums of every package file) and scan the whole filesystem for SUID files. This is slower. |
| `--only AREA…` / `--skip AREA…` | Choose areas: `overview hardware kernel packages network users services filesystem logs`. |
| `--timeout SEC` | Per-command timeout. The default is 60. |
| `--log-level`, `--log-json` | Progress logging on stderr. |

Exit codes:

- `0`: no critical or high findings.
- `1`: critical or high findings present. Useful for scripts.
- `2`: the audit could not write its report.
- `130`: interrupted.

## Usage Examples

```bash
sudo python archaudit.pyz                       # full audit → ~/Documents/ArchAudit
python archaudit.pyz --offline                  # quick, no network, no sudo
sudo python archaudit.pyz --deep                # thorough (several minutes)
python archaudit.pyz --only packages network    # just CVEs, updates, exposure
```

**Weekly audit with a systemd user timer.** It runs without root, so the run is
partial:

```ini
# ~/.config/systemd/user/archaudit.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python %h/bin/archaudit.pyz
SuccessExitStatus=1

# ~/.config/systemd/user/archaudit.timer
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
```

Enable it with:

```bash
systemctl --user enable --now archaudit.timer
```

**In Obsidian:**

1. Choose *Open folder as vault*, select `~/Documents/ArchAudit`, and open
   **Audit History** or the newest run's **00 Dashboard**.
2. Tags like `#severity/high` and `#category/network`, plus the front-matter fields,
   work with search, the graph view and the optional Dataview plugin.

**Sample output.** This is a simulated Arch system with a few deliberate problems; see
`sample-vault/`:

```text
Arch audit complete for testbox: 3 critical, 7 high, 10 medium, 10 low, 1 info;
3 item(s) not collected.
Open in Obsidian: ~/Documents/ArchAudit/2026-10-07 1456 testbox/00 Dashboard.md
```

| ID | Severity | Finding |
|---|---|---|
| C01 | 🟥 Critical | Vulnerable package: openssl |
| C02 | 🟥 Critical | Accounts with an empty password |
| H01 | 🟧 High | CPU mitigations disabled on the kernel command line |
| H03 | 🟧 High | Redis (often unauthenticated) listening on all interfaces (port 6379) |
| M02 | 🟨 Medium | Kernel upgraded but system not rebooted |
| M05 | 🟨 Medium | No active firewall detected |
| … | | |

## Security Review

**Weaknesses identified:**

1. **Trust in local tools.** If root is already compromised, `pacman`, `ss` and similar
   can lie. archaudit is a hygiene tool, not a forensic or rootkit detector. For an
   incident, boot trusted media and use dedicated IR tooling.
2. **Static check knowledge.** The known-SUID list, risky ports and sysctl baselines
   live in code and will age. They are kept as data tables at the top of each module so
   they're easy to update.
3. **Heuristic severities.** Context matters: a desktop's port 22 differs from a
   server's. Severities follow common baselines and should be adjusted to your threat
   model.
4. **Output format drift.** `arch-audit` output is parsed as text. Lines in an
   unexpected format are shown raw and recorded as "not collected" instead of being
   dropped.
5. **`--deep` can be slow** on large `/home` or `/` trees. It stays on one filesystem
   and doesn't follow symlinks.

**Performance.**

- A typical run takes 5–30 seconds. Most of that is `arch-audit` and `checkupdates`
  (network) and `pacman -Qk`.
- The filesystem walks are I/O-bound.
- Memory stays small: raw output is capped at 256 KB per command, and the `pacman.log`
  read at 64 MB.

**Scalability.** It is designed for one host per run. For a fleet:

1. Run it on each host, for example with a systemd timer.
2. Collect the per-run `findings.json` files, which have stable finding keys.
3. Aggregate them centrally.

**Tests (30, included):**

- Parser tests: `arch-audit` variants (including colour codes and the testing-repo
  form), `SigLevel` risk, both `pacman.log` timestamp formats, `ss`, sshd
  first-match/Include/Match handling, password states, sysctl comparisons and Markdown
  escaping.
- End-to-end tests on a simulated Arch root:
  - the expected findings are produced;
  - no password hashes leak;
  - a non-root run records gaps instead of guessing;
  - missing tools and `--offline` are reported;
  - a crashing collector becomes a gap instead of failing the audit;
  - every wikilink in the vault resolves;
  - file permissions are correct;
  - new and resolved findings are tracked across scans;
  - a symlinked file in the vault is replaced, not followed;
  - XDG Documents paths are honoured.

**Suggested additional tests:**

- Run it inside a real Arch container (`archlinux:latest`) in CI, with and without root.
- Property-based fuzzing of the parsers.
- A golden-file test of a full vault.

## Future Improvements

- More checks:
  - Lynis-style kernel module blacklists;
  - `faillock` state;
  - ClamAV/rkhunter results if installed;
  - Flatpak permission review;
  - Docker/Podman container exposure;
  - TPM/LUKS keyslot details.
- AUR package version checks against the AUR RPC, as an opt-in network check.
- A "Remediation plan" note that orders fixes by effort and impact.
- An HTML export and a JSON-to-SIEM forwarder for fleets.
- Per-finding "accepted risk" notes that persist across runs, so known items stop
  showing as new.
