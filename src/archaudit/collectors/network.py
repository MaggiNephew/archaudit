"""Network configuration, listening services, firewall and SSH server checks."""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass

from archaudit import md
from archaudit.collectors._util import active, unit_states
from archaudit.core import Context, GapKind, Note, Severity

CAT = "Network"

FIREWALL_UNITS = ("nftables.service", "firewalld.service", "ufw.service",
                  "iptables.service", "ip6tables.service", "opensnitchd.service")
NETWORK_MANAGERS = ("NetworkManager.service", "systemd-networkd.service", "iwd.service",
                    "dhcpcd.service", "connman.service", "systemd-resolved.service")

# Ports that are risky to expose beyond localhost.
RISKY_PORTS: dict[int, tuple[Severity, str]] = {
    23: (Severity.HIGH, "Telnet (cleartext remote login)"),
    2375: (Severity.CRITICAL, "Docker API without TLS (root-equivalent)"),
    21: (Severity.MEDIUM, "FTP (cleartext)"),
    111: (Severity.MEDIUM, "rpcbind"),
    139: (Severity.MEDIUM, "NetBIOS/SMB"),
    445: (Severity.MEDIUM, "SMB"),
    3306: (Severity.MEDIUM, "MySQL/MariaDB"),
    5432: (Severity.MEDIUM, "PostgreSQL"),
    6379: (Severity.HIGH, "Redis (often unauthenticated)"),
    11211: (Severity.HIGH, "memcached"),
    27017: (Severity.HIGH, "MongoDB"),
    5900: (Severity.MEDIUM, "VNC"),
    3389: (Severity.MEDIUM, "RDP"),
}

_PROC = re.compile(r'\(\("([^"]+)"')


@dataclass(frozen=True, slots=True)
class Listener:
    proto: str
    address: str
    port: int
    process: str

    @property
    def scope(self) -> str:
        if self.address in ("*", ""):
            return "all interfaces"
        try:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address = \
                ipaddress.ip_address(self.address)
        except ValueError:
            return "specific address"
        # "::ffff:127.0.0.1" is IPv4 loopback seen through a dual-stack socket.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip.is_unspecified:
            return "all interfaces"
        if ip.is_loopback:
            return "localhost"
        if ip.is_multicast:
            return "multicast group"
        if ip.is_link_local:
            return "link-local"
        return "specific address"

    @property
    def exposed(self) -> bool:
        """Accepts connections from other hosts. Multicast group memberships
        (e.g. mDNS on 224.0.0.251) are listed but are not listening services."""
        return self.scope in ("all interfaces", "specific address")


def parse_ss(text: str) -> list[Listener]:
    """Parse ``ss -H -tulpn`` output."""
    out: list[Listener] = []
    for line in text.splitlines():
        parts = line.split(maxsplit=6)
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        host, _, port = local.rpartition(":")
        # ss prints "[fe80::1]%wlo1" and "127.0.0.53%lo": drop the scope, then brackets.
        host = host.split("%", 1)[0].strip("[]")
        if not port.isdigit():
            continue
        proc = _PROC.search(parts[6]) if len(parts) > 6 else None
        out.append(Listener(proto, host, int(port), proc.group(1) if proc else ""))
    # ss lists v4 and v6 separately; keep unique entries in a stable order.
    return sorted(set(out), key=lambda item: (item.port, item.proto, item.address))


def parse_sshd_config(ctx: Context, path: str = "/etc/ssh/sshd_config",
                      _seen: set[str] | None = None, base: str = "/etc/ssh") -> dict[str, str]:
    """Effective global sshd options (first value wins, Include expanded,
    parsing stops at the first ``Match`` block). ``base`` resolves relative
    Include paths (``/ProgramData/ssh`` on Windows)."""
    seen = _seen if _seen is not None else set()
    if path in seen:
        return {}
    seen.add(path)
    text = ctx.read(path)
    if text is None:
        return {}
    opts: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        key, value = key.lower(), value.strip().strip('"')
        if key == "match":
            break
        if key == "include":
            for pattern in value.split():
                pattern = pattern.replace("\\", "/")
                if not pattern.startswith("/") and ":" not in pattern:
                    pattern = f"{base}/{pattern}"
                directory, _, glob = pattern.rpartition("/")
                for name in ctx.listdir(directory):
                    if fnmatch.fnmatch(name, glob):
                        for k, v in parse_sshd_config(ctx, f"{directory}/{name}", seen,
                                                      base).items():
                            opts.setdefault(k, v)
            continue
        opts.setdefault(key, value)
    return opts


def collect_network(ctx: Context) -> list[Note]:
    note = Note("Network", CAT, tags=["network"])
    ctx.set_note(note.title)

    if res := ctx.cmd(["ip", "-j", "addr", "show"], category=CAT, what="Network interfaces",
                      raw_name="ip addr"):
        rows = []
        try:
            for iface in json.loads(res.stdout):
                addrs = [f"{a.get('local')}/{a.get('prefixlen')}"
                         for a in iface.get("addr_info", [])]
                rows.append((iface.get("ifname"), iface.get("operstate"),
                             iface.get("address", ""), ", ".join(addrs)))
        except (json.JSONDecodeError, AttributeError):
            ctx.gap("Network interfaces", CAT, GapKind.ERROR, "unparseable `ip -j addr`")
        note.add(md.heading("Interfaces"),
                 md.table(("Interface", "State", "MAC", "Addresses"), rows))

    if res := ctx.cmd(["ip", "-j", "route", "show"], category=CAT, what="Routing table",
                      raw_name="ip route"):
        try:
            routes = [(r.get("dst"), r.get("gateway", ""), r.get("dev"), r.get("protocol", ""))
                      for r in json.loads(res.stdout)]
            note.add(md.heading("Routes"),
                     md.table(("Destination", "Gateway", "Device", "Protocol"), routes))
        except (json.JSONDecodeError, AttributeError):
            ctx.gap("Routing table", CAT, GapKind.ERROR, "unparseable `ip -j route`")

    resolv = ctx.read("/etc/resolv.conf") or ""
    nameservers = [ln.split()[1] for ln in resolv.splitlines()
                   if ln.startswith("nameserver") and len(ln.split()) > 1]
    managers = active(ctx, NETWORK_MANAGERS)
    forwarding = (ctx.read("/proc/sys/net/ipv4/ip_forward") or "").strip()
    note.add(md.heading("Configuration"),
             md.kv_table([("DNS servers", ", ".join(nameservers) or "none"),
                          ("Network management services", ", ".join(managers) or "none detected"),
                          ("IPv4 forwarding", {"1": "enabled", "0": "disabled"}.get(forwarding,
                                                                                    "unknown"))]))
    if hosts := ctx.read("/etc/hosts"):
        note.add(md.callout("example", "/etc/hosts", md.code(hosts), folded=True))

    firewall_active = _firewall(ctx, note)
    exposed_ports = _listeners(ctx, note, firewall_active)
    note.summary = (f"{exposed_ports if exposed_ports is not None else 'unknown'} "
                    f"network-reachable port(s), firewall: "
                    f"{'active' if firewall_active else 'none detected'}")
    return [note, _ssh(ctx)]


def _firewall(ctx: Context, note: Note) -> bool:
    running = active(ctx, FIREWALL_UNITS)
    ruleset_rules: int | None = None
    if ctx.is_root and ctx.has("nft"):
        if res := ctx.cmd(["nft", "list", "ruleset"], category=CAT,
                          what="nftables ruleset", raw_name="nft ruleset"):
            ruleset_rules = sum(1 for ln in res.lines
                                if ln.strip() and not ln.strip().startswith(("table", "chain",
                                                                             "}", "type")))
            note.add(md.callout("example", "nftables ruleset", md.code(res.stdout, "nft"),
                                folded=True))
    elif not ctx.is_root:
        ctx.gap("Firewall rules (nftables ruleset)", CAT, GapKind.NEEDS_ROOT,
                "`nft list ruleset` requires root")
    has_rules = bool(ruleset_rules)
    note.add(md.heading("Firewall"),
             md.kv_table([("Firewall services active", ", ".join(running) or "none"),
                          ("nftables rules loaded", ruleset_rules if ruleset_rules is not None
                           else "unknown (needs root)")]))
    if not running and not has_rules:
        ctx.finding(
            "No active firewall detected", Severity.MEDIUM, CAT,
            "No firewall service is running" + ("" if ctx.is_root else
            " (ruleset could not be inspected without root)") +
            ". Any service listening on a network interface is reachable by other hosts "
            "on the same network, e.g. public Wi-Fi.",
            _firewall_hint(ctx),
            references=["https://wiki.archlinux.org/title/Uncomplicated_Firewall",
                        "https://wiki.archlinux.org/title/Nftables"],
        )
    return bool(running) or has_rules


def _firewall_hint(ctx: Context) -> str:
    match ctx.platform.family:
        case "fedora":
            return "`sudo systemctl enable --now firewalld` (Fedora's default firewall)."
        case "debian":
            return ("Enable a simple default-deny inbound firewall: `sudo apt install ufw && "
                    "sudo ufw default deny incoming && sudo ufw enable`.")
    return ("Enable a simple default-deny inbound firewall, e.g. `sudo pacman -S ufw && "
            "sudo ufw default deny incoming && sudo ufw enable && "
            "sudo systemctl enable --now ufw`, or use nftables/firewalld.")


SSH_UNITS = ("sshd.service", "ssh.service")  # Arch/Fedora, Debian/Ubuntu


def _listeners(ctx: Context, note: Note, firewall_active: bool) -> int | None:
    """Report listening sockets; returns the number of network-reachable ports."""
    res = ctx.cmd(["ss", "-H", "-tulpn"], category=CAT, what="Listening ports",
                  raw_name="ss -tulpn")
    if res is None:
        return None
    return report_listeners(ctx, note, parse_ss(res.stdout), firewall_active,
                            partial_processes=not ctx.is_root)


def report_listeners(ctx: Context, note: Note, listeners: list[Listener],
                     firewall_active: bool, *, partial_processes: bool,
                     risky_ports: dict[int, tuple[Severity, str]] | None = None) -> int:
    """Shared by the Linux and Windows network collectors."""
    risky_ports = RISKY_PORTS if risky_ports is None else risky_ports
    if partial_processes and any(not item.process for item in listeners):
        ctx.gap("Process names for listening ports", CAT, GapKind.NEEDS_ROOT,
                "only processes owned by the current user are shown")
    note.add(md.heading("Listening ports"), md.table(
        ("Proto", "Address", "Port", "Reachable from", "Process"),
        [(item.proto, item.address, item.port, item.scope, item.process or "?")
         for item in listeners]))

    # One entry per (protocol, port): IPv4 and IPv6 sockets of the same
    # service count once. This is the number shown everywhere.
    ports: dict[tuple[str, int], list[Listener]] = {}
    for item in listeners:
        if item.exposed:
            ports.setdefault((item.proto, item.port), []).append(item)
    ctx.facts["exposed_ports"] = str(len(ports))

    risky: dict[int, list[Listener]] = {}
    for (_, port), items in ports.items():
        if port in risky_ports:
            risky.setdefault(port, []).extend(items)
    for port, items in sorted(risky.items()):
        sev, name = risky_ports[port]
        first = min(items, key=lambda x: x.scope != "all interfaces")
        names = sorted({x.process for x in items if x.process})
        ctx.finding(
            f"{name} listening on {first.scope} (port {port})", sev, CAT,
            f"{name} is reachable from the network on port {port}"
            f"{' (' + ', '.join(names) + ')' if names else ''}.",
            "Bind it to 127.0.0.1 if only local use is needed, require authentication/TLS, "
            "or block the port in the firewall. Disable the service if unused.",
            evidence="\n".join(f"{x.proto} {x.address}:{x.port} {x.process}" for x in items),
            key=f"risky-port-{port}",
        )
    if ports:
        lines = []
        for (proto, port), items in sorted(ports.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            procs = ", ".join(sorted({x.process for x in items if x.process})) or "?"
            addrs = ", ".join(sorted({x.address for x in items}))
            lines.append(f"{proto} {port} ({procs}) on {addrs}")
        ctx.finding(
            f"{len(ports)} network-reachable port(s)",
            Severity.LOW if firewall_active else Severity.MEDIUM, CAT,
            "These ports accept connections from other hosts (not just localhost). Each is "
            "attack surface; "
            + ("a firewall is active, so check that it filters these ports."
               if firewall_active else "no firewall was detected to filter them."),
            "Stop services you don't need, bind local-only services to 127.0.0.1, and "
            "filter the rest with a firewall.",
            evidence="\n".join(lines),
            key="exposed-ports",
        )
    return len(ports)


def _ssh(ctx: Context) -> Note:
    note = Note("SSH Server", CAT, tags=["network", "ssh"])
    ctx.set_note(note.title)
    if not (ctx.exists("/usr/bin/sshd") or ctx.exists("/usr/sbin/sshd") or ctx.has("sshd")):
        note.summary = "OpenSSH server not installed"
        note.add(md.callout("success", "Not installed", "No SSH server attack surface."))
        return note

    states = unit_states(ctx, SSH_UNITS)
    enabled = unit_states(ctx, SSH_UNITS, verb="is-enabled")
    running = any(s == "active" for s in states.values())
    unit = next((u for u in SSH_UNITS if states.get(u) == "active"), SSH_UNITS[0])
    source = "sshd_config files"
    opts: dict[str, str] = {}
    # `sshd -T` needs host keys, so on a machine where sshd was installed but
    # never set up it fails; that is "not in use", not a collection error.
    if running and ctx.is_root:
        res = ctx.cmd(["sshd", "-T"], category=CAT, what="Effective sshd config",
                      raw_name="sshd -T")
        if res:
            opts = {k.lower(): v for k, _, v in (ln.partition(" ") for ln in res.lines)}
            source = "`sshd -T` (effective)"
    if not opts:
        opts = parse_sshd_config(ctx)
        if running and not ctx.is_root:
            ctx.gap("Effective sshd configuration", CAT, GapKind.NEEDS_ROOT,
                    "parsed config files instead of `sshd -T` (Match blocks ignored)")

    def get(key: str, default: str) -> str:
        return opts.get(key, default).lower()

    settings = {
        "Port": opts.get("port", "22"),
        "PermitRootLogin": get("permitrootlogin", "prohibit-password"),
        "PasswordAuthentication": get("passwordauthentication", "yes"),
        "KbdInteractiveAuthentication": get("kbdinteractiveauthentication", "yes"),
        "PermitEmptyPasswords": get("permitemptypasswords", "no"),
        "PubkeyAuthentication": get("pubkeyauthentication", "yes"),
        "X11Forwarding": get("x11forwarding", "no"),
        "MaxAuthTries": opts.get("maxauthtries", "6"),
        "AllowUsers / AllowGroups": " ".join(filter(None, (opts.get("allowusers"),
                                                            opts.get("allowgroups")))),
    }
    note.summary = f"sshd {'running' if running else 'not running'}, " \
                   f"root login: {settings['PermitRootLogin']}"
    note.add(md.kv_table([("Service state", states.get(unit, "unknown")),
                          ("Enabled at boot", enabled.get(unit, "unknown")),
                          ("Settings source", source)]),
             md.heading("Settings"), md.kv_table(list(settings.items())))
    if not running:
        note.add(md.callout("info", "sshd is not running",
                            "Settings are reported for reference only."))
        return note

    refs = ["https://wiki.archlinux.org/title/OpenSSH#Protection"]
    if settings["PermitEmptyPasswords"] == "yes":
        ctx.finding("SSH allows empty passwords", Severity.CRITICAL, CAT,
                    "Accounts without a password can log in over the network.",
                    "Set `PermitEmptyPasswords no` and restart sshd.", references=refs)
    if settings["PermitRootLogin"] == "yes":
        ctx.finding("SSH permits direct root login", Severity.HIGH, CAT,
                    "Root can log in directly over SSH, making root the prime brute-force "
                    "target and removing per-user accountability.",
                    "Set `PermitRootLogin no` in `/etc/ssh/sshd_config.d/10-hardening.conf` "
                    "and `sudo systemctl restart sshd`.", references=refs)
    if "yes" in (settings["PasswordAuthentication"], settings["KbdInteractiveAuthentication"]):
        ctx.finding("SSH accepts password logins", Severity.MEDIUM, CAT,
                    "Password or keyboard-interactive authentication is enabled (OpenSSH's "
                    "default when unset), so the server can be brute-forced.",
                    "Set up key-based login first, then set `PasswordAuthentication no` and "
                    "`KbdInteractiveAuthentication no`; consider `fail2ban`/`sshguard`.",
                    evidence=f"PasswordAuthentication={settings['PasswordAuthentication']}, "
                             f"KbdInteractiveAuthentication="
                             f"{settings['KbdInteractiveAuthentication']}",
                    references=refs)
    if settings["X11Forwarding"] == "yes":
        ctx.finding("SSH X11 forwarding enabled", Severity.LOW, CAT,
                    "X11 forwarding exposes the client's display to the server side.",
                    "Set `X11Forwarding no` unless you need it.", references=refs)
    return note
