"""Windows collectors against canned PowerShell JSON (runs on any OS)."""

import json
import re
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeRunner

from archaudit.cli import run_audit
from archaudit.collectors import WINDOWS_COLLECTORS, collectors_for
from archaudit.collectors.windows import (
    logs,
    network,
    security,
    services,
    storage,
    system,
    updates,
    users,
)
from archaudit.collectors.windows._ps import as_list, ps_argv
from archaudit.core import Context, GapKind, Severity
from archaudit.platforms import Platform
from archaudit.writer import VaultWriter

WIN = Platform("windows", "windows", "Windows", "windows")
LINK = re.compile(r"\[\[([^\]|\\]+)")

OVERVIEW = {"Caption": "Microsoft Windows 11 Pro", "Version": "10.0.22000", "Build": 22000,
            "UBR": 2538, "DisplayVersion": "21H2", "EditionID": "Professional",
            "InstallDate": "2022-01-10T12:00:00", "LastBoot": "2026-11-01T08:00:00",
            "Hostname": "WINBOX", "Domain": "WORKGROUP", "PartOfDomain": False,
            "Architecture": "64-bit", "TimeZone": "Pacific Standard Time", "Locale": "en-US"}
HARDWARE = {"Manufacturer": "LENOVO", "Model": "ThinkPad", "MemoryBytes": 17179869184,
            "SystemType": 2, "CPU": "Intel Core i7", "CPUVendor": "GenuineIntel", "Cores": 4,
            "Threads": 8, "MaxMHz": 2800, "VirtFirmware": True, "BIOSVendor": "LENOVO",
            "BIOSVersion": "N1", "BIOSDate": "2022-01-01", "GPUs": "Intel Iris Xe",
            "Batteries": {"Name": "BAT0", "Charge": 80}, "Disks": []}
PLATFORM = {"UEFI": True, "SecureBoot": 0, "VBSStatus": 0, "ServicesRunning": [],
            "ServicesConfigured": [], "RunAsPPL": None, "WDigest": 1, "DEP": 2,
            "SmartScreen": "RequireAdmin", "Tpm": None, "TpmError": None}
DEFENDER = {"Status": {"ServiceEnabled": True, "AntivirusEnabled": True, "RealTime": False,
                       "Behavior": False, "TamperProtected": False, "SignatureAgeDays": 30,
                       "QuickScanAgeDays": 90, "Mode": "Normal"},
            "StatusError": None,
            "Preferences": {"ExclusionPath": ["C:\\Users\\sam\\Downloads", "D:\\Games"],
                            "ExclusionProcess": [], "ExclusionExtension": "exe",
                            "PUAProtection": 0, "NetworkProtection": 0, "CloudProtection": 2},
            "Products": {"Name": "Windows Defender", "State": 393472}}
UPDATES = {"Pending": [
    {"Title": "2026-10 Cumulative Update for Windows 11 (KB5099999)", "Severity": "Critical",
     "KB": "5099999", "Categories": "Security Updates, Windows 11"},
    {"Title": "Intel - Display - 31.0", "Severity": "", "KB": "", "Categories": "Drivers"},
    {"Title": "Security Intelligence Update for Microsoft Defender", "Severity": "",
     "KB": "2267602", "Categories": "Definition Updates, Microsoft Defender Antivirus"}],
    "LastInstall": "2026-06-01T10:00:00", "LastInstallTitle": "2026-05 Cumulative Update",
    "RebootPending": True, "NoAutoUpdate": 1, "ServiceStart": "Manual",
    "Hotfixes": [{"Id": "KB5050000", "Description": "Security Update", "InstalledOn": "2026-06-01"}]}
SOFTWARE = [{"Name": "7-Zip", "Version": "24.08", "Publisher": "Igor Pavlov"}]
NETWORK = {"Firewall": [{"Name": "Domain", "Enabled": "True", "Inbound": "NotConfigured"},
                        {"Name": "Private", "Enabled": "True", "Inbound": "NotConfigured"},
                        {"Name": "Public", "Enabled": "False", "Inbound": "NotConfigured"}],
           "Listeners": [
               {"Proto": "tcp", "Address": "0.0.0.0", "Port": 445, "Process": "System"},
               {"Proto": "tcp", "Address": "0.0.0.0", "Port": 3389, "Process": "svchost"},
               {"Proto": "tcp", "Address": "0.0.0.0", "Port": 5985, "Process": "System"},
               {"Proto": "tcp", "Address": "127.0.0.1", "Port": 6463, "Process": "Discord"},
               {"Proto": "udp", "Address": "::", "Port": 5353, "Process": "chrome"}],
           "Profiles": {"Name": "CafeWiFi", "Interface": "Wi-Fi", "Category": "Public"},
           "Addresses": [], "DNS": [], "SMB": None, "SMB1Reg": 1, "RDPDeny": 0, "RDPNLA": 0,
           "LLMNR": None, "NetBIOS": [{"Adapter": "Intel Wi-Fi", "Option": 0}], "SSHD": ""}
USERS = {"Users": [
    {"Name": "Administrator", "Enabled": True, "SID": "S-1-5-21-1-2-3-500",
     "PasswordRequired": True, "PasswordLastSet": None, "LastLogon": None, "Source": "Local"},
    {"Name": "Guest", "Enabled": True, "SID": "S-1-5-21-1-2-3-501", "PasswordRequired": False,
     "PasswordLastSet": None, "LastLogon": None, "Source": "Local"},
    {"Name": "sam", "Enabled": True, "SID": "S-1-5-21-1-2-3-1001", "PasswordRequired": False,
     "PasswordLastSet": "2026-01-01T00:00:00", "LastLogon": "2026-11-06T08:00:00",
     "Source": "Local"}],
    "Admins": [{"Name": "WINBOX\\Administrator", "SID": "S-1-5-21-1-2-3-500", "Source": "Local"},
               {"Name": "WINBOX\\sam", "SID": "S-1-5-21-1-2-3-1001", "Source": "Local"}],
    "AdminsError": None, "CurrentUser": "WINBOX\\sam", "CurrentSid": "S-1-5-21-1-2-3-1001",
    "EnableLUA": 0, "ConsentPromptBehaviorAdmin": 0, "PromptOnSecureDesktop": 0,
    "LocalAccountTokenFilterPolicy": 1, "AutoAdminLogon": "1", "AutoLogonPasswordStored": True,
    "AlwaysInstallElevatedHKLM": 1, "AlwaysInstallElevatedHKCU": 1}
SERVICES = {"Services": [
    {"Name": "VendorSvc", "Display": "Vendor Service", "State": "Running", "Start": "Auto",
     "Account": "LocalSystem", "Path": "C:\\Program Files\\Vendor App\\svc.exe -k",
     "Exe": "C:\\Program Files\\Vendor App\\svc.exe", "WeakExe": None, "WeakDir": None},
    {"Name": "Updater", "Display": "Updater", "State": "Running", "Start": "Auto",
     "Account": "LocalSystem", "Path": "\"C:\\Tools\\upd.exe\"", "Exe": "C:\\Tools\\upd.exe",
     "WeakExe": "BUILTIN\\Users: Modify, Synchronize", "WeakDir": None},
    {"Name": "RemoteRegistry", "Display": "Remote Registry", "State": "Running",
     "Start": "Auto", "Account": "NT AUTHORITY\\LocalService",
     "Path": "C:\\Windows\\system32\\svchost.exe -k localService",
     "Exe": "C:\\Windows\\system32\\svchost.exe", "WeakExe": None, "WeakDir": None}],
    "Tasks": {"Name": "Backup", "Path": "\\", "State": "Ready", "User": "SYSTEM",
              "RunLevel": "Highest", "Action": "C:\\Users\\Public\\b.exe",
              "WeakExe": "Everyone: FullControl"},
    "Run": [{"Key": "HKCU:\\...\\Run", "Name": "Discord", "Command": "Update.exe"}],
    "Startup": []}
STORAGE = {"SystemDrive": "C:", "BitLocker": None,
           "BitLockerError": "Access denied", "ShellState": 2,
           "Disks": {"Drive": "C:", "FS": "NTFS", "Size": 500 * 1024**3, "Free": 20 * 1024**3},
           "PathDirs": [{"Dir": "C:\\Windows\\system32", "Exists": True, "Weak": None},
                        {"Dir": "C:\\Python27", "Exists": False,
                         "Weak": "NT AUTHORITY\\Authenticated Users: AppendData"}]}
LOGS = {"Failed": [{"User": "admin", "IP": "203.0.113.9", "LogonType": "3"}] * 25,
        "RDP": [], "Cleared": ["2026-10-30T03:00:00"], "SystemErrors": ["x: disk error"],
        "ScriptBlockLogging": None, "SecurityLogMB": 20}


def responses(**override: Any) -> dict[tuple[str, ...], tuple[int, str, str]]:
    data = {system.OVERVIEW: OVERVIEW, system.HARDWARE: HARDWARE,
            security.PLATFORM: PLATFORM, security.DEFENDER: DEFENDER,
            updates.updates_script(True): UPDATES, updates.updates_script(False): UPDATES,
            updates.SOFTWARE: SOFTWARE, network.NETWORK: NETWORK, users.USERS: USERS,
            services.SERVICES: SERVICES, storage.STORAGE: STORAGE, logs.LOGS: LOGS}
    for script, value in override.items():
        data[getattr(system, script, None) or getattr(logs, script)] = value
    return {tuple(ps_argv(script)): (0, json.dumps(value), "") for script, value in data.items()}


def _audit(tmp_path: Path, is_root: bool = True, resp: Any = None,
           **kw: Any) -> tuple[Any, FakeRunner]:
    runner = FakeRunner(resp or responses(), {"powershell.exe"})
    ctx = Context(root=tmp_path, runner=runner, is_root=is_root, platform=WIN, **kw)
    return run_audit(ctx, list(WINDOWS_COLLECTORS)), runner


def test_registry_and_area_names() -> None:
    assert collectors_for(WIN) is WINDOWS_COLLECTORS
    assert {"overview", "network", "users", "packages", "logs"} <= set(WINDOWS_COLLECTORS)


def test_windows_findings(tmp_path: Path) -> None:
    result, _ = _audit(tmp_path)
    t = {f.title: f.severity for f in result.findings}
    expected = {
        "Windows 11 21H2 no longer receives security updates": Severity.HIGH,
        "Secure Boot is disabled": Severity.MEDIUM,
        "Memory integrity (HVCI) is off": Severity.MEDIUM,
        "LSA protection is off": Severity.LOW,
        "WDigest stores logon passwords in memory": Severity.HIGH,
        "No active real-time antivirus": Severity.HIGH,
        "Broad Defender exclusions": Severity.MEDIUM,
        "1 Windows security update(s) pending": Severity.HIGH,
        "1 other Windows update(s) pending": Severity.LOW,   # definitions are not counted
        "Restart required to finish installing updates": Severity.MEDIUM,
        "Automatic Windows updates are disabled": Severity.MEDIUM,
        "Windows Firewall is off for some network profiles": Severity.HIGH,  # Public
        "SMBv1 is enabled": Severity.HIGH,
        "Remote Desktop accepts connections without Network Level Authentication":
            Severity.HIGH,
        "WinRM over HTTP listening on all interfaces (port 5985)": Severity.MEDIUM,
        "Legacy name resolution (LLMNR / NetBIOS) is enabled": Severity.LOW,
        "Guest account is enabled": Severity.HIGH,
        "Built-in Administrator account is enabled": Severity.MEDIUM,
        "Enabled accounts that do not require a password": Severity.MEDIUM,
        "Your everyday account is an administrator": Severity.LOW,
        "User Account Control is disabled": Severity.HIGH,
        "Remote UAC restrictions are disabled": Severity.MEDIUM,
        "Automatic logon is enabled with a password stored in the registry": Severity.HIGH,
        "Any user can install MSI packages as SYSTEM (AlwaysInstallElevated)": Severity.HIGH,
        "Service binaries or folders writable by non-admin users": Severity.HIGH,
        "Scheduled task programs writable by non-admin users": Severity.HIGH,
        "Unquoted service paths with spaces": Severity.MEDIUM,
        "Legacy/risky service running: Remote Registry": Severity.MEDIUM,
        "System drive is not encrypted": Severity.MEDIUM,     # laptop (battery)
        "Writable folder in the system PATH": Severity.HIGH,  # missing C:\Python27
        "Drive nearly full": Severity.LOW,
        "Password guessing: 25 failed network logons in 30 days": Severity.MEDIUM,
        "The Security event log was cleared": Severity.HIGH,
        "PowerShell script block logging is off": Severity.INFO,
    }
    missing = {k: v for k, v in expected.items() if t.get(k) is not v}
    assert not missing, (missing, sorted(t))
    # SMB 445 and RDP 3389 are covered by their own checks, not "risky port" findings
    assert not any("port 445" in x or "port 3389" in x for x in t)
    assert result.facts["exposed_ports"] == "4"  # 445, 3389, 5985 tcp + 5353 udp on ::
    assert result.facts["root_encrypted"] == "no"
    assert result.facts["hostname"] == "WINBOX"


def test_non_admin_gaps_and_partial_data(tmp_path: Path) -> None:
    resp = responses(LOGS={"FailedError": "Attempted to perform an unauthorized operation.",
                           "RDPError": "Attempted to perform an unauthorized operation.",
                           "ClearedError": "Attempted to perform an unauthorized operation.",
                           "SystemErrors": [], "ScriptBlockLogging": 1, "SecurityLogMB": None})
    result, _ = _audit(tmp_path, is_root=False, resp=resp)
    kinds = {(g.item, g.kind) for g in result.gaps}
    assert ("Failed logons (Security log, 30 days)", GapKind.NEEDS_ROOT) in kinds
    assert ("BitLocker details", GapKind.NEEDS_ROOT) in kinds
    gap = next(g for g in result.gaps if g.kind is GapKind.NEEDS_ROOT)
    assert "administrator" in gap.fix.lower() and "sudo" not in gap.fix
    assert not any(f.title.startswith("Password guessing") for f in result.findings)


def test_missing_powershell_and_bad_json(tmp_path: Path) -> None:
    runner = FakeRunner({}, set())
    ctx = Context(root=tmp_path, runner=runner, is_root=True, platform=WIN)
    result = run_audit(ctx, list(WINDOWS_COLLECTORS))
    assert result.findings == []
    assert all(g.kind is GapKind.MISSING_TOOL for g in result.gaps)

    bad = responses()
    bad[tuple(ps_argv(network.NETWORK))] = (0, "WARNING: something\n{not json", "")
    result, _ = _audit(tmp_path, resp=bad)
    assert any(g.item == "Network configuration" and g.kind is GapKind.ERROR
               for g in result.gaps)


def test_offline_uses_cached_update_catalogue(tmp_path: Path) -> None:
    _, runner = _audit(tmp_path, offline=True)
    assert tuple(ps_argv(updates.updates_script(False))) in runner.calls
    assert tuple(ps_argv(updates.updates_script(True))) not in runner.calls


def test_windows_vault_links(tmp_path: Path) -> None:
    result, _ = _audit(tmp_path / "root")
    vault = tmp_path / "vault"
    run = VaultWriter(vault).write(result)
    broken = [f"{n.name} -> {t}" for n in vault.rglob("*.md") for t in LINK.findall(n.read_text())
              if not (vault / f"{t}.md").is_file()]
    assert not broken, broken
    data = json.loads((run / "findings.json").read_text())
    assert data["platform"] == "windows"
    dash = (run / "00 Dashboard.md").read_text()
    assert "Microsoft Windows 11 Pro" in dash
    gaps = (run / "02 Not Collected.md").read_text()
    assert "pacman" not in gaps


@pytest.mark.parametrize(("build", "edition", "today", "supported"), [
    (26100, "Professional", date(2026, 10, 13), True),
    (26100, "Professional", date(2026, 10, 14), False),
    (26100, "Enterprise", date(2026, 10, 14), True),
    (26200, "Core", date(2026, 11, 6), True),
    (19045, "Professional", date(2026, 1, 1), False),
    (99999, "Professional", date(2030, 1, 1), True),   # unknown future build: assume supported
])
def test_support_status(build: int, edition: str, today: date, supported: bool) -> None:
    assert system.support_status(build, edition, today)[2] is supported


@pytest.mark.parametrize(("path", "exe", "hit"), [
    ("C:\\Program Files\\A B\\s.exe -k", "C:\\Program Files\\A B\\s.exe", True),
    ("\"C:\\Program Files\\A B\\s.exe\" -k", "C:\\Program Files\\A B\\s.exe", False),
    ("C:\\Tools\\s.exe", "C:\\Tools\\s.exe", False),
    ("C:\\Windows\\System32\\svchost.exe -k x", "C:\\Windows\\System32\\svchost.exe", False),
])
def test_unquoted_path(path: str, exe: str, hit: bool) -> None:
    assert services.unquoted_path(path, exe) is hit


def test_risky_exclusions_and_helpers() -> None:
    assert security.risky_exclusion("C:\\")
    assert security.risky_exclusion("C:\\Users\\sam\\Downloads")
    assert security.risky_exclusion("C:\\Temp\\*")
    assert not security.risky_exclusion("D:\\Games\\SteamLibrary")
    assert as_list(None) == [] and as_list({"a": 1}) == [{"a": 1}]
    assert security._product_on(397568) and not security._product_on(393472)


def test_scripts_are_constant_and_encoded() -> None:
    argv = ps_argv(network.NETWORK)
    assert argv[:5] == ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                        "-EncodedCommand"]
    assert len(" ".join(argv)) < 32000  # Windows command-line limit
    for script in (system.OVERVIEW, system.HARDWARE, security.PLATFORM, security.DEFENDER,
                   updates.updates_script(True), updates.SOFTWARE, network.NETWORK,
                   users.USERS, services.SERVICES, storage.STORAGE, logs.LOGS):
        assert len(" ".join(ps_argv(script))) < 32000
        assert "ConvertTo-Json" in script
        # read-only: no cmdlets that change state
        assert not re.search(r"\b(Set|New-Item|Remove|Stop|Start|Restart|Enable|Disable|"
                             r"Install|Uninstall|Add)-[A-Z]", script)
