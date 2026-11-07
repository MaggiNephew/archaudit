"""Run fixed, read-only PowerShell scripts and parse their JSON output.

Every Windows check is a constant script in this package: nothing from the
system or the user is ever interpolated into a script. Scripts are passed with
``-EncodedCommand`` (base64 UTF-16LE), which avoids all command-line quoting
pitfalls, and return a single JSON document.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from archaudit.core import Context, GapKind

POWERSHELL = "powershell.exe"  # Windows PowerShell 5.1 ships with every Windows 10/11

# Shared prelude: stop on errors, UTF-8 output, no progress noise on stderr,
# and a registry reader that returns $null for missing keys/values.
PRELUDE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
function Reg([string]$Path, [string]$Name) {
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}
"""

# ACL helper shared by scripts that look for files/folders non-admins can modify.
# Well-known SIDs avoid localized account names: Everyone, BUILTIN\Users,
# Authenticated Users, INTERACTIVE.
WEAK_ACL = r"""
$WeakSids = 'S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-4'
$FileRights = '(^|, )(FullControl|Modify|Write|WriteData|ChangePermissions|TakeOwnership|268435456|1073741824)(,|$)'
$DirRights = '(^|, )(FullControl|Modify|Write|WriteData|CreateFiles|AppendData|ChangePermissions|TakeOwnership|268435456|1073741824)(,|$)'
function WeakAcl([string]$Path, [bool]$IsDir = $false) {
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($r in $acl.Access) {
            if ($r.AccessControlType -ne 'Allow') { continue }
            if ([string]$r.PropagationFlags -match 'InheritOnly') { continue }
            $sid = try { $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
            $pattern = if ($IsDir) { $DirRights } else { $FileRights }
            if ($WeakSids -contains $sid -and ([string]$r.FileSystemRights -match $pattern)) {
                return "$($r.IdentityReference): $($r.FileSystemRights)"
            }
        }
    } catch { }
    return $null
}
"""


def ps_argv(script: str) -> list[str]:
    encoded = base64.b64encode((PRELUDE + script).encode("utf-16-le")).decode("ascii")
    return [POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


def ps_json(ctx: Context, script: str, *, category: str, what: str, name: str,
            timeout: float | None = None) -> Any:
    """Run ``script`` and return its parsed JSON, or None (with a gap) on failure."""
    res = ctx.cmd(ps_argv(script), category=category, what=what, raw_name=name,
                  label=f"PowerShell: {name}", timeout=timeout)
    if res is None:
        return None
    text = res.stdout.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        ctx.gap(what, category, GapKind.ERROR, "PowerShell returned output that is not JSON",
                "Please report this together with the Raw note")
        return None


def as_list(value: Any) -> list[Any]:
    """PowerShell serialises a one-element array as a bare object; normalise."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def denied(message: Any) -> bool:
    text = str(message or "").lower()
    return any(m in text for m in ("access is denied", "access denied", "unauthorized",
                                   "requires elevation", "administrator", "0x80041003"))
