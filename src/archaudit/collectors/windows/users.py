"""Windows local accounts, administrators, UAC and credential exposure.

Nothing secret leaves PowerShell: for the auto-logon password the script only
reports *whether* one is stored.
"""

from __future__ import annotations

from typing import Any

from archaudit import md
from archaudit.collectors.windows._ps import as_dict, as_list, ps_json
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Users & Access"

USERS = r"""
$admins = @(); $adminsError = $null
try {
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.Name; SID = [string]$_.SID.Value; Source = [string]$_.PrincipalSource } })
} catch {
    # Get-LocalGroupMember fails on some machines (orphaned or Entra ID SIDs); fall back to ADSI.
    try {
        $group = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $admins = @(([ADSI]"WinNT://./$group,group").psbase.Invoke('Members') | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null); SID = ''; Source = 'ADSI' } })
    } catch { $adminsError = $_.Exception.Message }
}
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
[pscustomobject]@{
    Users = @(Get-LocalUser | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.Name; Enabled = [bool]$_.Enabled; SID = [string]$_.SID.Value
                           PasswordRequired = [bool]$_.PasswordRequired
                           PasswordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('s') } else { $null }
                           LastLogon = if ($_.LastLogon) { $_.LastLogon.ToString('s') } else { $null }
                           Source = [string]$_.PrincipalSource } })
    Admins = $admins; AdminsError = $adminsError
    CurrentUser = [string]$me.Name; CurrentSid = [string]$me.User.Value
    EnableLUA = Reg $sys 'EnableLUA'; ConsentPromptBehaviorAdmin = Reg $sys 'ConsentPromptBehaviorAdmin'
    PromptOnSecureDesktop = Reg $sys 'PromptOnSecureDesktop'
    LocalAccountTokenFilterPolicy = Reg $sys 'LocalAccountTokenFilterPolicy'
    AutoAdminLogon = [string](Reg $wl 'AutoAdminLogon')
    AutoLogonPasswordStored = [bool](Reg $wl 'DefaultPassword')
    AlwaysInstallElevatedHKLM = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    AlwaysInstallElevatedHKCU = Reg 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
} | ConvertTo-Json -Depth 4 -Compress
"""

_CONSENT = {0: "elevate without prompting", 1: "credentials on secure desktop",
            2: "consent on secure desktop", 3: "credentials", 4: "consent",
            5: "consent for non-Windows binaries (default)"}


def collect_users(ctx: Context) -> list[Note]:
    note = Note("Users & Access", CAT, tags=["users", "access", "uac", "windows"])
    ctx.set_note(note.title)
    d = as_dict(ps_json(ctx, USERS, category=CAT, what="Local accounts", name="local users"))
    if not d:
        note.summary = "not collected"
        return [note]
    users = [as_dict(u) for u in as_list(d.get("Users"))]
    admins = [as_dict(a) for a in as_list(d.get("Admins"))]
    if d.get("AdminsError"):
        ctx.gap("Administrators group members", CAT, GapKind.ERROR, str(d["AdminsError"])[:200])
    admin_sids = {a.get("SID") for a in admins if a.get("SID")}
    admin_names = {str(a.get("Name", "")).split("\\")[-1].lower() for a in admins}

    def is_admin(u: dict[str, Any]) -> bool:
        return u.get("SID") in admin_sids or str(u.get("Name", "")).lower() in admin_names

    enabled = [u for u in users if u.get("Enabled")]
    note.summary = f"{len(enabled)} enabled local account(s), {len(admins)} administrator(s)"
    note.add(md.heading("Local accounts"), md.table(
        ("User", "Enabled", "Administrator", "Password required", "Password set", "Last logon"),
        [(u.get("Name"), "yes" if u.get("Enabled") else "no", "yes" if is_admin(u) else "",
          "yes" if u.get("PasswordRequired") else "**no**", u.get("PasswordLastSet"),
          u.get("LastLogon")) for u in users]),
        md.heading("Administrators group"),
        md.table(("Member", "Source"), [(a.get("Name"), a.get("Source")) for a in admins]))

    _accounts(ctx, users, enabled, is_admin, d)
    _uac(ctx, note, d)
    _credentials(ctx, d)
    return [note]


def _accounts(ctx: Context, users: list[dict[str, Any]], enabled: list[dict[str, Any]],
              is_admin: Any, d: dict[str, Any]) -> None:
    for u in enabled:
        sid = str(u.get("SID", ""))
        if sid.endswith("-501"):
            ctx.finding("Guest account is enabled", Severity.HIGH, CAT,
                        "The built-in Guest account allows logging in without a personal "
                        "account and is a known foothold.",
                        "`Disable-LocalUser -Name '" + str(u.get("Name")) + "'` (admin "
                        "PowerShell).", key="guest-enabled")
        elif sid.endswith("-500"):
            ctx.finding("Built-in Administrator account is enabled", Severity.MEDIUM, CAT,
                        "The built-in Administrator (RID 500) is exempt from UAC prompts by "
                        "default and is the first account attackers guess.",
                        "Use a named administrator account and `Disable-LocalUser -Name '"
                        + str(u.get("Name")) + "'`.", key="builtin-admin")
    no_pw = [str(u.get("Name")) for u in enabled
             if not u.get("PasswordRequired") and not str(u.get("SID", "")).endswith("-501")]
    if no_pw:
        ctx.finding(
            "Enabled accounts that do not require a password", Severity.MEDIUM, CAT,
            "These local accounts are allowed to have an empty password. Windows blocks blank "
            "passwords for network logons by default, but anyone at the keyboard can sign in.",
            "Set a password (`net user <user> *`) and require one from now on "
            "(`net user <user> /passwordreq:yes`), or disable unused accounts.",
            evidence="\n".join(no_pw), key="password-not-required",
        )
    current = str(d.get("CurrentUser", "")).split("\\")[-1].lower()
    me = next((u for u in users if str(u.get("Name", "")).lower() == current), None)
    if me is not None and is_admin(me):
        ctx.finding(
            "Your everyday account is an administrator", Severity.LOW, CAT,
            "Anything you run can ask for administrator rights with a single click on the UAC "
            "prompt. A standard account forces a password for elevation, which stops many "
            "drive-by installs.",
            "Create a separate administrator account, then make this one a standard user "
            "(Settings → Accounts → Other users).",
            evidence=str(d.get("CurrentUser")), key="daily-admin",
        )


def _uac(ctx: Context, note: Note, d: dict[str, Any]) -> None:
    lua, consent = d.get("EnableLUA"), d.get("ConsentPromptBehaviorAdmin")
    secure = d.get("PromptOnSecureDesktop")
    note.add(md.heading("User Account Control"), md.kv_table([
        ("UAC", "off" if lua == 0 else "on"),
        ("Admin prompt behaviour", _CONSENT.get(consent, "default") if isinstance(consent, int)
         else "default"),
        ("Prompt on secure desktop", "no" if secure == 0 else "yes"),
        ("Remote UAC restrictions (LocalAccountTokenFilterPolicy)",
         "disabled" if d.get("LocalAccountTokenFilterPolicy") == 1 else "enabled"),
    ]))
    if lua == 0:
        ctx.finding("User Account Control is disabled", Severity.HIGH, CAT,
                    "With UAC off, every program an administrator runs gets full rights "
                    "without any prompt.",
                    "Set `EnableLUA` to 1 (or use Control Panel → User Account Control "
                    "settings) and restart.", key="uac-off")
    elif consent == 0:
        ctx.finding("UAC elevates administrators without prompting", Severity.MEDIUM, CAT,
                    "Programs started by an administrator can silently gain full rights.",
                    "Control Panel → User Account Control settings → move the slider to the "
                    "default (second from top).", key="uac-no-prompt")
    if secure == 0 and lua != 0:
        ctx.finding("UAC prompts are not shown on the secure desktop", Severity.LOW, CAT,
                    "Other programs can interact with or spoof UAC prompts.",
                    "Set `PromptOnSecureDesktop` to 1 (UAC slider at the default level).",
                    key="uac-secure-desktop")
    if d.get("LocalAccountTokenFilterPolicy") == 1:
        ctx.finding("Remote UAC restrictions are disabled", Severity.MEDIUM, CAT,
                    "`LocalAccountTokenFilterPolicy = 1` gives local administrator accounts "
                    "full rights over the network, which makes pass-the-hash lateral movement "
                    "easy.",
                    "Delete the value under `HKLM\\SOFTWARE\\Microsoft\\Windows\\"
                    "CurrentVersion\\Policies\\System` unless a management tool requires it.",
                    key="remote-uac")


def _credentials(ctx: Context, d: dict[str, Any]) -> None:
    if d.get("AutoAdminLogon") == "1":
        stored = bool(d.get("AutoLogonPasswordStored"))
        ctx.finding(
            "Automatic logon is enabled" + (" with a password stored in the registry"
                                            if stored else ""),
            Severity.HIGH if stored else Severity.MEDIUM, CAT,
            "Windows signs in automatically at boot, so anyone with the device is logged in."
            + (" The password is stored in plain text under the Winlogon registry key, where "
               "any administrator-level process can read it." if stored else ""),
            "Turn off automatic sign-in (`netplwiz` → require a password) and delete "
            "`DefaultPassword` under `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
            "Winlogon`. Sysinternals Autologon stores it encrypted if you really need it.",
            key="autologon",
        )
    if d.get("AlwaysInstallElevatedHKLM") == 1 and d.get("AlwaysInstallElevatedHKCU") == 1:
        ctx.finding(
            "Any user can install MSI packages as SYSTEM (AlwaysInstallElevated)",
            Severity.HIGH, CAT,
            "With `AlwaysInstallElevated` set in both HKLM and HKCU, any user can run an MSI "
            "file with SYSTEM rights: a one-step privilege escalation.",
            "Set both `AlwaysInstallElevated` policy values to 0 (gpedit: Windows Installer → "
            "Always install with elevated privileges: Disabled).",
            key="always-install-elevated",
        )
