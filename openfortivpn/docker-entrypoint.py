#!/usr/bin/env python3
"""Entrypoint for the openfortivpn gateway container.

Reads configuration from environment variables, pins a route to the VPN
gateway on the physical uplink, installs a killswitch firewall (filter,
NAT and mangle, IPv4 and IPv6) plus policy routing so published ports stay
reachable, then keeps an openfortivpn session alive (reconnecting forever).

Standard library only. All `ip`/`iptables` interaction goes through
:class:`Runner`, which keeps the logic unit-testable without root.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

POLICY_TABLE = "200"
POLICY_MARK = "0x1"
RECONCILE_INTERVAL = 10.0
MONITOR_INTERVAL = 2.0
IPV4_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
PORT_RE = re.compile(r"^[0-9]+$")
DELAY_RE = re.compile(r"^[0-9]+([.][0-9]+)?$")


def log(msg: str) -> None:
    stamp = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"{stamp} [openfortivpn] {msg}", flush=True)


def warn(msg: str) -> None:
    log(f"WARN: {msg}")


class FatalError(Exception):
    """Fatal startup/runtime error. main() logs it and exits 1."""


def is_on(value: str) -> bool:
    return value.strip().lower() in ("on", "1", "yes", "true")


def split_list(value: str) -> list[str]:
    """Split comma- and/or space-separated env var into clean tokens."""
    return [tok for tok in value.replace(",", " ").split() if tok]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class Config:
    host: str = ""
    port: int = 443
    user: str = ""
    password: str = ""
    password_file: str = ""
    otp: str = ""
    otp_file: str = ""
    realm: str = ""
    trusted_cert: str = ""
    client_cert: str = ""
    client_key: str = ""
    ca_file: str = ""
    sni: str = ""
    set_dns: str = "0"
    pppd_peerdns: str = "0"
    half_internet_routes: str = "0"
    insecure_ssl: str = "0"
    min_tls: str = ""
    set_routes: str = "1"
    full_tunnel: str = "on"
    routes: list[str] = field(default_factory=list)
    exclude_routes: list[str] = field(default_factory=list)
    reconnect_delay: float = 5.0
    extra_args: str = ""
    firewall_enabled: str = "on"
    lan_iface: str = ""
    lan_subnet: str = ""
    dns_servers: str = ""
    config_file: str = "/etc/openfortivpn/config"

    @classmethod
    def from_env(cls, env: dict[str, str]) -> Config:
        def get(key: str, default: str = "") -> str:
            return env.get(key, default)

        cfg = cls(
            host=get("VPN_HOST"),
            user=get("VPN_USER"),
            password=get("VPN_PASSWORD"),
            password_file=get("VPN_PASSWORD_FILE"),
            otp=get("VPN_OTP"),
            otp_file=get("VPN_OTP_FILE"),
            realm=get("VPN_REALM"),
            trusted_cert=get("VPN_TRUSTED_CERT"),
            client_cert=get("VPN_CLIENT_CERT"),
            client_key=get("VPN_CLIENT_KEY"),
            ca_file=get("VPN_CA_FILE"),
            sni=get("VPN_SNI"),
            set_dns=get("VPN_SET_DNS", "0"),
            pppd_peerdns=get("VPN_PPPD_PEERDNS", "0"),
            half_internet_routes=get("VPN_HALF_INTERNET_ROUTES", "0"),
            insecure_ssl=get("VPN_INSECURE_SSL", "0"),
            min_tls=get("VPN_MIN_TLS"),
            set_routes=get("VPN_SET_ROUTES", "1"),
            full_tunnel=get("VPN_FULL_TUNNEL", "on"),
            routes=split_list(get("VPN_ROUTES")),
            exclude_routes=split_list(get("VPN_EXCLUDE_ROUTES", "100.64.0.0/10")),
            extra_args=get("VPN_EXTRA_ARGS"),
            firewall_enabled=get("FIREWALL_ENABLED", "on"),
            lan_iface=get("LAN_IFACE"),
            lan_subnet=get("LAN_SUBNET"),
            dns_servers=get("DNS_SERVERS"),
            config_file=get("CONFIG_FILE", "/etc/openfortivpn/config"),
        )
        port_raw = get("VPN_PORT", "443")
        if not PORT_RE.match(port_raw) or not 1 <= int(port_raw) <= 65535:
            raise FatalError("VPN_PORT must be an integer from 1 to 65535")
        cfg.port = int(port_raw)
        delay_raw = get("VPN_RECONNECT_DELAY", "5")
        if not DELAY_RE.match(delay_raw):
            raise FatalError("VPN_RECONNECT_DELAY must be a non-negative number")
        cfg.reconnect_delay = float(delay_raw)
        if not cfg.host:
            raise FatalError("VPN_HOST is required")
        if cfg.password and cfg.password_file:
            raise FatalError("set only one of VPN_PASSWORD and VPN_PASSWORD_FILE")
        if cfg.otp and cfg.otp_file:
            raise FatalError("set only one of VPN_OTP and VPN_OTP_FILE")
        if cfg.set_routes not in ("0", "1"):
            raise FatalError("VPN_SET_ROUTES must be 0 or 1")

        def normalize_ipv4_cidrs(cidrs: list[str]) -> list[str]:
            normalized = []
            for cidr in cidrs:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    raise FatalError(
                        f"invalid CIDR in VPN_ROUTES/VPN_EXCLUDE_ROUTES: {cidr}"
                    )
                if network.version != 4:
                    raise FatalError(
                        f"only IPv4 CIDRs are supported in VPN_ROUTES/"
                        f"VPN_EXCLUDE_ROUTES: {cidr}"
                    )
                normalized.append(str(network))
            return normalized

        cfg.routes = normalize_ipv4_cidrs(cfg.routes)
        cfg.exclude_routes = normalize_ipv4_cidrs(cfg.exclude_routes)
        return cfg


# ---------------------------------------------------------------------------
# Command execution (mockable seam for tests)
# ---------------------------------------------------------------------------
class Runner:
    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(list(argv), capture_output=True, text=True, check=False)

    def ok(self, argv: Sequence[str]) -> bool:
        return self.run(argv).returncode == 0

    def has(self, cmd: str) -> bool:
        """Whether a binary exists on PATH (mockable for hermetic tests)."""
        return shutil.which(cmd) is not None

    def out(self, argv: Sequence[str]) -> str:
        proc = self.run(argv)
        return proc.stdout if proc.returncode == 0 else ""


# ---------------------------------------------------------------------------
# Network inspection helpers (pure parsing, unit-tested)
# ---------------------------------------------------------------------------
def resolve_ipv4(runner: Runner, host: str) -> list[str]:
    """Resolve a hostname to sorted unique IPv4 addresses (busybox-safe)."""
    if IPV4_RE.match(host):
        return [host]
    if type(runner) is Runner:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            resolved = sorted({str(sockaddr[0]) for _, _, _, _, sockaddr in infos})
            if resolved:
                return resolved
        except OSError:
            pass
    proc = runner.run(["nslookup", host])
    found: set[str] = set()
    in_answer = False
    for line in proc.stdout.replace("\r", "").splitlines():
        lower = line.lower()
        if "answer:" in lower or lower.startswith("name:"):
            in_answer = True
        if not in_answer:
            continue
        parts = line.split()
        if not parts:
            continue
        candidate = ""
        if parts[0] == "Address:" and len(parts) >= 2:
            candidate = parts[1]
        elif parts[0] == "Address" and len(parts) >= 3:
            candidate = parts[2]
        if IPV4_RE.match(candidate):
            found.add(candidate)
    return sorted(found)


def parse_default_route(line: str) -> tuple[str, str]:
    """Parse `ip route show default` line into (dev, via-gateway-or-"")."""
    dev, gw = "", ""
    tokens = line.split()
    for i, tok in enumerate(tokens):
        if tok == "dev" and i + 1 < len(tokens) and not dev:
            dev = tokens[i + 1]
        elif tok == "via" and i + 1 < len(tokens) and not gw:
            gw = tokens[i + 1]
    return dev, gw


def detect_uplink(runner: Runner) -> tuple[str, str]:
    out = runner.out(["ip", "-4", "route", "show", "default"])
    first = out.splitlines()[0] if out.splitlines() else ""
    dev, gw = parse_default_route(first)
    if not dev:
        raise FatalError("no IPv4 default route found")
    return dev, gw


def current_ppp_iface(runner: Runner) -> str | None:
    for line in runner.out(["ip", "-o", "link", "show"]).splitlines():
        parts = line.split(": ")
        if len(parts) >= 2 and parts[1].startswith("ppp"):
            return parts[1]
    return None


def iface_has_ipv4(runner: Runner, iface: str) -> bool:
    return "inet " in runner.out(["ip", "-4", "addr", "show", iface])


def default_route_dev(runner: Runner) -> str | None:
    out = runner.out(["ip", "-4", "route", "show", "default"])
    if not out.splitlines():
        return None
    dev, _ = parse_default_route(out.splitlines()[0])
    return dev or None


def connected_subnets(runner: Runner, dev: str) -> list[str]:
    """Directly attached subnets on an interface (for INPUT + docs)."""
    subnets = []
    for line in runner.out(["ip", "-4", "route", "show", "dev", dev]).splitlines():
        first = line.split()[0] if line.split() else ""
        if "/" not in first:
            continue
        try:
            subnets.append(str(ipaddress.ip_network(first, strict=False)))
        except ValueError:
            continue
    return subnets


def read_ipv4_nameservers(path: str = "/etc/resolv.conf") -> list[str]:
    """Return unique IPv4 resolvers configured in resolv.conf."""
    try:
        with open(path) as fh:
            lines = fh.readlines()
    except OSError:
        return []
    resolvers: set[str] = set()
    for line in lines:
        parts = line.split()
        if len(parts) < 2 or parts[0] != "nameserver":
            continue
        try:
            address = ipaddress.ip_address(parts[1])
        except ValueError:
            continue
        if address.version == 4:
            resolvers.add(str(address))
    return sorted(resolvers)


# ---------------------------------------------------------------------------
# Runtime context
# ---------------------------------------------------------------------------
@dataclass
class Ctx:
    cfg: Config
    runner: Runner
    uplink_dev: str = ""
    uplink_gw: str = ""
    lan_iface: str = ""
    server_ips: list[str] = field(default_factory=list)
    dns_resolvers: list[str] = field(default_factory=list)
    ipt: str = "iptables"
    ip6t: str = "ip6tables"
    stopping: bool = False
    shut_down: bool = False
    stop_event: threading.Event = field(default_factory=threading.Event)
    configured_iface: str = ""
    proc: subprocess.Popen | None = None
    original_resolv_file: str = "/run/openfortivpn-resolv.conf"
    hosts_file: str = "/etc/hosts"

    def request_stop(self) -> None:
        self.stopping = True
        self.stop_event.set()


# ---------------------------------------------------------------------------
# iptables helpers (idempotent: check-then-add)
# ---------------------------------------------------------------------------
def ipt_ok(ctx: Ctx, table: str, *args: str) -> bool:
    return ctx.runner.ok([ctx.ipt, "-t", table] + list(args))


def try_ensure(ctx: Ctx, table: str, check: list[str], add: list[str]) -> bool:
    """Check-then-add for idempotent iptables/ip setup. True if present."""
    if ctx.runner.ok([ctx.ipt, "-t", table, *check]):
        return True
    return ctx.runner.ok([ctx.ipt, "-t", table, *add])


def ensure_chain(ctx: Ctx, table: str, chain: str) -> None:
    if not try_ensure(ctx, table, ["-N", chain], ["-F", chain]):
        raise FatalError(f"could not prepare {table}/{chain}")


def ensure_chain_exists(ctx: Ctx, table: str, chain: str) -> bool:
    """Ensure a chain exists without flushing its contents if it already does."""
    if ctx.runner.ok([ctx.ipt, "-t", table, "-S", chain]):
        return True
    return ctx.runner.ok([ctx.ipt, "-t", table, "-N", chain])


def ensure_jump(ctx: Ctx, table: str, parent: str, child: str) -> None:
    if not try_ensure(
        ctx, table, ["-C", parent, "-j", child], ["-I", parent, "1", "-j", child]
    ):
        raise FatalError(f"could not attach {table}/{child} to {parent}")


def ensure_rule(ctx: Ctx, table: str, chain: str, spec: list[str], what: str) -> None:
    if ctx.runner.ok([ctx.ipt, "-t", table, "-C", chain] + spec):
        return
    if ctx.runner.ok([ctx.ipt, "-t", table, "-A", chain] + spec):
        return
    raise FatalError(what)


def ensure_rule_first(
    ctx: Ctx, table: str, chain: str, spec: list[str], what: str
) -> None:
    """Ensure a rule precedes an existing terminal rule in a managed chain."""
    if ctx.runner.ok([ctx.ipt, "-t", table, "-C", chain] + spec):
        return
    if ctx.runner.ok([ctx.ipt, "-t", table, "-I", chain, "1"] + spec):
        return
    raise FatalError(what)


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
def refresh_credentials(ctx: Ctx) -> None:
    cfg = ctx.cfg
    if cfg.password_file:
        try:
            with open(cfg.password_file) as fh:
                cfg.password = fh.read().strip()
        except OSError:
            raise FatalError(f"could not read {cfg.password_file}")
    if cfg.otp_file:
        try:
            with open(cfg.otp_file) as fh:
                cfg.otp = fh.read().strip()
        except OSError:
            raise FatalError(f"could not read {cfg.otp_file}")


def create_ppp_device(ctx: Ctx) -> None:
    if os.path.exists("/dev/ppp"):
        return
    log("creating /dev/ppp device node")
    made = ctx.runner.ok(["mknod", "/dev/ppp", "c", "108", "0"])
    if not made:
        warn("could not create /dev/ppp; pass --device=/dev/ppp or run privileged")


def enable_forwarding(ctx: Ctx) -> None:
    log("enabling IPv4 forwarding and loose reverse path filtering")
    params = [
        ("/proc/sys/net/ipv4/ip_forward", "1"),
        ("/proc/sys/net/ipv4/conf/default/rp_filter", "2"),
    ]
    if ctx.lan_iface:
        params.append((f"/proc/sys/net/ipv4/conf/{ctx.lan_iface}/rp_filter", "2"))
    if ctx.uplink_dev and ctx.uplink_dev != ctx.lan_iface:
        params.append((f"/proc/sys/net/ipv4/conf/{ctx.uplink_dev}/rp_filter", "2"))
    for path, val in params:
        try:
            with open(path) as fh:
                if fh.read().strip() == val:
                    continue
            with open(path, "w") as fh:
                fh.write(val)
        except OSError:
            warn(f"could not set {path}")


def render_config(cfg: Config) -> str:
    lines = [
        "# generated by the openfortivpn entrypoint",
        f"host = {cfg.host}",
        f"port = {cfg.port}",
    ]
    optional = [
        ("username", cfg.user),
        ("password", cfg.password),
        ("otp", cfg.otp),
        ("realm", cfg.realm),
        ("trusted-cert", cfg.trusted_cert),
        ("user-cert", cfg.client_cert),
        ("user-key", cfg.client_key),
        ("ca-file", cfg.ca_file),
        ("sni", cfg.sni),
        ("min-tls", cfg.min_tls),
    ]
    lines += [f"{key} = {val}" for key, val in optional if val]
    lines += [
        f"set-dns = {cfg.set_dns}",
        f"pppd-use-peerdns = {cfg.pppd_peerdns}",
        f"half-internet-routes = {cfg.half_internet_routes}",
        f"insecure-ssl = {cfg.insecure_ssl}",
        f"set-routes = {cfg.set_routes}",
        "persistent = 0",
    ]
    return "\n".join(lines) + "\n"


def write_config(ctx: Ctx) -> None:
    directory = os.path.dirname(ctx.cfg.config_file) or "."
    try:
        os.makedirs(directory, exist_ok=True)
        with open(ctx.cfg.config_file, "w") as fh:
            fh.write(render_config(ctx.cfg))
        os.chmod(ctx.cfg.config_file, 0o600)
    except OSError:
        raise FatalError(f"could not write {ctx.cfg.config_file}")


def remove_config(ctx: Ctx) -> None:
    path = ctx.cfg.config_file
    if path and os.path.exists(path):
        try:
            with open(path, "w") as fh:
                fh.write("")
            os.remove(path)
        except OSError:
            pass


def pin_server_routes(ctx: Ctx, max_retries: int = 5, retry_delay: float = 2.0) -> None:
    """Resolve and pin gateway IPs + /etc/hosts to the uplink."""
    cfg = ctx.cfg
    ips = resolve_ipv4(ctx.runner, cfg.host)
    retries = 0
    while not ips and retries < max_retries and not ctx.stopping:
        retries += 1
        warn(
            f"could not resolve {cfg.host} (attempt {retries}/{max_retries}), "
            f"retrying in {retry_delay}s..."
        )
        ctx.stop_event.wait(retry_delay)
        ips = resolve_ipv4(ctx.runner, cfg.host)
    if ctx.stopping:
        return
    if not ips:
        raise FatalError(f"could not resolve {cfg.host} to an IPv4 address")
    ctx.server_ips = ips
    log(f"VPN gateway {cfg.host} resolves to: {' '.join(ips)}")
    for ip in ips:
        if cfg.host != ip:
            try:
                with open(ctx.hosts_file, "a") as fh:
                    fh.write(f"{ip}\t{cfg.host} # openfortivpn gateway\n")
            except OSError:
                raise FatalError(f"could not pin {cfg.host} in {ctx.hosts_file}")
        route = (
            [
                "ip",
                "route",
                "replace",
                f"{ip}/32",
                "via",
                ctx.uplink_gw,
                "dev",
                ctx.uplink_dev,
            ]
            if ctx.uplink_gw
            else ["ip", "route", "replace", f"{ip}/32", "dev", ctx.uplink_dev]
        )
        if not ctx.runner.ok(route):
            raise FatalError(f"could not pin route to {ip}")


def allow_vpn_control(ctx: Ctx) -> None:
    """Open only the resolved VPN control endpoints in the closed killswitch."""
    for ip in ctx.server_ips:
        ensure_rule_first(
            ctx,
            "filter",
            "OFV_OUTPUT",
            [
                "-o",
                ctx.uplink_dev,
                "-d",
                ip,
                "-p",
                "tcp",
                "--dport",
                str(ctx.cfg.port),
                "-j",
                "ACCEPT",
            ],
            f"could not allow VPN control traffic to {ip}",
        )


def via_uplink(ctx: Ctx, dest: str) -> list[str]:
    if ctx.uplink_gw:
        return [
            "ip",
            "route",
            "replace",
            dest,
            "via",
            ctx.uplink_gw,
            "dev",
            ctx.uplink_dev,
        ]
    return ["ip", "route", "replace", dest, "dev", ctx.uplink_dev]


def pin_dns_routes(ctx: Ctx) -> None:
    """Keep non-loopback resolvers reachable across default-route changes."""
    for resolver in ctx.dns_resolvers:
        if ipaddress.ip_address(resolver).is_loopback:
            continue
        if not ctx.runner.ok(via_uplink(ctx, f"{resolver}/32")):
            raise FatalError(f"could not pin route to DNS resolver {resolver}")


def apply_exclude_routes(ctx: Ctx, quiet: bool = False) -> None:
    """Keep listed subnets on the uplink (outbound direction)."""
    for cidr in ctx.cfg.exclude_routes:
        if ctx.runner.ok(via_uplink(ctx, cidr)):
            if not quiet:
                log(f"excluded {cidr} from tunnel via {ctx.uplink_dev}")
        elif not quiet:
            warn(f"could not exclude {cidr} from tunnel")


def setup_policy_routing(ctx: Ctx, quiet: bool = False) -> bool:
    """Route replies to inbound connections via the uplink (table 200).

    Only marked (inbound-initiated) connections use it; locally initiated
    traffic keeps using the main table, i.e. the tunnel: no leak.
    Returns False (with warning) instead of raising: degraded but running.
    """
    if not ctx.uplink_dev:
        warn("skipping policy routing: no uplink device")
        return False
    if not ctx.runner.ok(via_uplink(ctx, "default") + ["table", POLICY_TABLE]):
        warn("could not set policy table default route")
        return False
    rules = ctx.runner.out(["ip", "rule", "show"])
    rule_present = any(
        f"fwmark {POLICY_MARK}" in line and f"lookup {POLICY_TABLE}" in line
        for line in rules.splitlines()
    )
    add_rule = ["ip", "rule", "add", "fwmark", POLICY_MARK, "table", POLICY_TABLE]
    if not rule_present and not ctx.runner.ok(add_rule):
        warn("policy routing unavailable (ip rule failed)")
        return False
    for chain in ("OFV_PREROUTING", "OFV_MARK_OUT"):
        if not ensure_chain_exists(ctx, "mangle", chain):
            warn(f"could not prepare mangle/{chain}")
            return False
    if not try_ensure(
        ctx,
        "mangle",
        ["-C", "PREROUTING", "-j", "OFV_PREROUTING"],
        ["-I", "PREROUTING", "1", "-j", "OFV_PREROUTING"],
    ):
        warn("could not attach mangle PREROUTING chain")
        return False
    mark_new = [
        "-i",
        ctx.uplink_dev,
        "-m",
        "conntrack",
        "--ctstate",
        "NEW",
        "-j",
        "CONNMARK",
        "--set-mark",
        POLICY_MARK,
    ]
    if not try_ensure(
        ctx,
        "mangle",
        ["-C", "OFV_PREROUTING"] + mark_new,
        ["-A", "OFV_PREROUTING"] + mark_new,
    ):
        warn("could not add inbound marking rule")
        return False
    if not try_ensure(
        ctx,
        "mangle",
        ["-C", "OUTPUT", "-j", "OFV_MARK_OUT"],
        ["-I", "OUTPUT", "1", "-j", "OFV_MARK_OUT"],
    ):
        warn("could not attach mangle OUTPUT chain")
        return False
    restore = ["-j", "CONNMARK", "--restore-mark"]
    if not try_ensure(
        ctx,
        "mangle",
        ["-C", "OFV_MARK_OUT"] + restore,
        ["-A", "OFV_MARK_OUT"] + restore,
    ):
        warn("could not add mark restore rule")
        return False
    if not quiet:
        log(f"inbound replies via {ctx.uplink_dev} (table {POLICY_TABLE})")
    return True


def select_backends(ctx: Ctx) -> None:
    r = ctx.runner
    if r.ok(["iptables", "-t", "nat", "-S", "DOCKER_OUTPUT"]):
        ctx.ipt, ctx.ip6t = "iptables", "ip6tables"
    elif r.has("iptables-legacy") and r.ok(
        ["iptables-legacy", "-t", "nat", "-S", "DOCKER_OUTPUT"]
    ):
        ctx.ipt, ctx.ip6t = "iptables-legacy", "ip6tables-legacy"
    elif r.ok(["iptables", "-L", "-n"]):
        ctx.ipt, ctx.ip6t = "iptables", "ip6tables"
    elif r.has("iptables-legacy") and r.ok(["iptables-legacy", "-L", "-n"]):
        ctx.ipt, ctx.ip6t = "iptables-legacy", "ip6tables-legacy"
    else:
        raise FatalError("no usable iptables backend; NET_ADMIN is required")


def setup_firewall(ctx: Ctx, has_ipv6: bool | None = None) -> None:
    cfg = ctx.cfg
    log(f"installing killswitch firewall ({ctx.ipt})")
    for table, chain in (
        ("filter", "OFV_OUTPUT"),
        ("filter", "OFV_INPUT"),
        ("filter", "OFV_FORWARD"),
        ("nat", "OFV_POSTROUTING"),
        ("mangle", "OFV_MANGLE_OUTPUT"),
        ("mangle", "OFV_MANGLE_FORWARD"),
    ):
        ensure_chain(ctx, table, chain)

    # --- OUTPUT: loopback, tunnel, marked inbound replies, control channel,
    # then drop everything else. Do not accept ESTABLISHED traffic generally:
    # a process sharing this namespace may have connected over the uplink
    # before startup, and such a rule would preserve that killswitch bypass.
    ensure_rule(
        ctx,
        "filter",
        "OFV_OUTPUT",
        ["-o", "lo", "-j", "ACCEPT"],
        "could not allow loopback traffic",
    )
    ensure_rule(
        ctx,
        "filter",
        "OFV_OUTPUT",
        ["-o", "ppp+", "-j", "ACCEPT"],
        "could not allow tunnel traffic",
    )
    ensure_rule(
        ctx,
        "filter",
        "OFV_OUTPUT",
        [
            "-o",
            ctx.uplink_dev,
            "-m",
            "mark",
            "--mark",
            POLICY_MARK,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        "could not allow marked inbound replies",
    )
    for resolver in ctx.dns_resolvers:
        if ipaddress.ip_address(resolver).is_loopback:
            continue
        for protocol in ("udp", "tcp"):
            ensure_rule(
                ctx,
                "filter",
                "OFV_OUTPUT",
                [
                    "-o",
                    ctx.uplink_dev,
                    "-d",
                    resolver,
                    "-p",
                    protocol,
                    "--dport",
                    "53",
                    "-j",
                    "ACCEPT",
                ],
                f"could not allow DNS traffic to {resolver}",
            )
    allow_vpn_control(ctx)
    # Docker's embedded resolver rides loopback. Direct resolvers are limited
    # to the exact addresses read from resolv.conf and port 53.
    ensure_rule(
        ctx,
        "filter",
        "OFV_OUTPUT",
        ["-j", "DROP"],
        "could not close the OUTPUT killswitch",
    )

    # --- INPUT: fail closed. Published ports arrive DNAT'd, so match the
    # DNAT state instead of enumerating ports (zero config). Also accept
    # traffic from directly attached subnets (docker-proxy/siblings).
    ensure_rule(
        ctx,
        "filter",
        "OFV_INPUT",
        ["-i", "lo", "-j", "ACCEPT"],
        "could not allow loopback input",
    )
    ensure_rule(
        ctx,
        "filter",
        "OFV_INPUT",
        ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        "could not allow established input",
    )
    ensure_rule(
        ctx,
        "filter",
        "OFV_INPUT",
        ["-i", "ppp+", "-j", "ACCEPT"],
        "could not allow tunnel input",
    )
    ensure_rule(
        ctx,
        "filter",
        "OFV_INPUT",
        ["-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"],
        "could not allow published ports",
    )
    for subnet in connected_subnets(ctx.runner, ctx.uplink_dev):
        ensure_rule(
            ctx,
            "filter",
            "OFV_INPUT",
            ["-i", ctx.uplink_dev, "-s", subnet, "-j", "ACCEPT"],
            f"could not allow local subnet {subnet}",
        )
    ensure_rule(
        ctx,
        "filter",
        "OFV_INPUT",
        [
            "-i",
            ctx.uplink_dev,
            "-p",
            "udp",
            "--sport",
            "67",
            "--dport",
            "68",
            "-j",
            "ACCEPT",
        ],
        "could not allow DHCP replies",
    )
    ensure_rule(
        ctx,
        "filter",
        "OFV_INPUT",
        ["-p", "icmp", "--icmp-type", "echo-request", "-j", "ACCEPT"],
        "could not allow ping",
    )
    ensure_rule(
        ctx,
        "filter",
        "OFV_INPUT",
        ["-j", "DROP"],
        "could not close the INPUT killswitch",
    )

    # --- FORWARD + NAT/MSS for gateway use.
    ensure_rule(
        ctx,
        "filter",
        "OFV_FORWARD",
        [
            "-i",
            "ppp+",
            "-o",
            ctx.lan_iface,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        "could not allow established forwarded traffic",
    )
    if cfg.lan_subnet:
        ensure_rule(
            ctx,
            "filter",
            "OFV_FORWARD",
            ["-s", cfg.lan_subnet, "-o", "ppp+", "-j", "ACCEPT"],
            "could not allow forwarded tunnel traffic",
        )
    else:
        ensure_rule(
            ctx,
            "filter",
            "OFV_FORWARD",
            ["-o", "ppp+", "-j", "ACCEPT"],
            "could not allow forwarded tunnel traffic",
        )
    ensure_rule(
        ctx,
        "filter",
        "OFV_FORWARD",
        ["-j", "DROP"],
        "could not close the FORWARD killswitch",
    )
    ensure_rule(
        ctx,
        "nat",
        "OFV_POSTROUTING",
        ["-o", "ppp+", "-j", "MASQUERADE"],
        "could not enable tunnel masquerading",
    )
    if not ipt_ok(
        ctx,
        "mangle",
        "-A",
        "OFV_MANGLE_FORWARD",
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-j",
        "TCPMSS",
        "--clamp-mss-to-pmtu",
    ):
        warn("forwarded TCP MSS clamping is unavailable")
    if not ipt_ok(
        ctx,
        "mangle",
        "-A",
        "OFV_MANGLE_OUTPUT",
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-j",
        "TCPMSS",
        "--clamp-mss-to-pmtu",
    ):
        warn("local TCP MSS clamping is unavailable")

    ensure_jump(ctx, "filter", "OUTPUT", "OFV_OUTPUT")
    ensure_jump(ctx, "filter", "INPUT", "OFV_INPUT")
    ensure_jump(ctx, "filter", "FORWARD", "OFV_FORWARD")
    ensure_jump(ctx, "nat", "POSTROUTING", "OFV_POSTROUTING")
    ensure_jump(ctx, "mangle", "OUTPUT", "OFV_MANGLE_OUTPUT")
    ensure_jump(ctx, "mangle", "FORWARD", "OFV_MANGLE_FORWARD")

    setup_ipv6_firewall(ctx, has_ipv6=has_ipv6)


def setup_ipv6_firewall(ctx: Ctx, has_ipv6: bool | None = None) -> None:
    """IPv4-only tunnels: fail IPv6 closed instead of leaking around it."""
    if has_ipv6 is None:
        has_ipv6 = os.path.exists("/proc/net/if_inet6")
    if not has_ipv6:
        return
    r = ctx.runner
    ip6t = ctx.ip6t
    if not r.has(ip6t):
        raise FatalError(f"IPv6 is active but {ip6t} is unavailable")

    def run6(*args: str) -> bool:
        return r.ok([ip6t] + list(args))

    for chain in ("OFV6_OUTPUT", "OFV6_INPUT", "OFV6_FORWARD"):
        if not run6("-N", chain) and not run6("-F", chain):
            raise FatalError(f"could not prepare the IPv6 {chain} killswitch")
    for spec in (
        ("OFV6_OUTPUT", ["-o", "lo", "-j", "ACCEPT"]),
        (
            "OFV6_OUTPUT",
            ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ),
        ("OFV6_INPUT", ["-i", "lo", "-j", "ACCEPT"]),
        (
            "OFV6_INPUT",
            ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ),
        ("OFV6_INPUT", ["-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"]),
        ("OFV6_INPUT", ["-p", "ipv6-icmp", "-j", "ACCEPT"]),  # NDP needs this
    ):
        chain, rule = spec
        if not run6("-C", chain, *rule) and not run6("-A", chain, *rule):
            raise FatalError(f"could not set IPv6 {chain} rule")
    for chain in ("OFV6_OUTPUT", "OFV6_INPUT", "OFV6_FORWARD"):
        if not run6("-A", chain, "-j", "DROP"):
            raise FatalError(f"could not close the IPv6 {chain} killswitch")
    for parent, child in (
        ("OUTPUT", "OFV6_OUTPUT"),
        ("INPUT", "OFV6_INPUT"),
        ("FORWARD", "OFV6_FORWARD"),
    ):
        if not run6("-C", parent, "-j", child) and not run6(
            "-I", parent, "1", "-j", child
        ):
            raise FatalError(f"could not attach the IPv6 {child} killswitch")


# ---------------------------------------------------------------------------
# Tunnel lifecycle
# ---------------------------------------------------------------------------
def apply_static_routes(ctx: Ctx, quiet: bool = False) -> None:
    """Extra per-network routes through the tunnel (opt-in VPN_ROUTES)."""
    iface = ctx.configured_iface
    for cidr in ctx.cfg.routes:
        if ctx.runner.ok(["ip", "route", "replace", cidr, "dev", iface]):
            if not quiet:
                log(f"routed {cidr} via {iface}")
        elif not quiet:
            warn(f"could not route {cidr} via {iface}")


def on_tunnel_up(ctx: Ctx, iface: str) -> None:
    log(f"tunnel is up on {iface}")
    if is_on(ctx.cfg.full_tunnel):
        if ctx.runner.ok(["ip", "route", "replace", "default", "dev", iface]):
            log(f"default route now points at {iface}")
        else:
            warn(f"could not set default route via {iface}")
    apply_exclude_routes(ctx)
    apply_static_routes(ctx)
    if ctx.cfg.dns_servers:
        try:
            servers = [f"nameserver {ns}\n" for ns in split_list(ctx.cfg.dns_servers)]
            with open("/etc/resolv.conf", "w") as fh:
                fh.writelines(servers)
            log(f"using DNS servers: {ctx.cfg.dns_servers}")
        except OSError:
            warn("could not write /etc/resolv.conf")


def on_tunnel_down(ctx: Ctx) -> None:
    log("tunnel went down")
    if ctx.uplink_dev and not ctx.runner.ok(via_uplink(ctx, "default")):
        warn("could not restore the physical default route")
    if ctx.cfg.dns_servers and os.path.exists(ctx.original_resolv_file):
        try:
            with (
                open(ctx.original_resolv_file, "rb") as src,
                open("/etc/resolv.conf", "wb") as dst,
            ):
                dst.write(src.read())
        except OSError:
            warn("could not restore /etc/resolv.conf")


def reconcile(ctx: Ctx) -> None:
    """Re-enforce routing invariants; pppd likes to rewrite main table."""
    if not ctx.configured_iface:
        return
    if (
        is_on(ctx.cfg.full_tunnel)
        and default_route_dev(ctx.runner) != ctx.configured_iface
    ):
        if ctx.runner.ok(
            ["ip", "route", "replace", "default", "dev", ctx.configured_iface]
        ):
            log(f"default route now points at {ctx.configured_iface} (reconciled)")
        else:
            warn("could not re-apply default route via tunnel")
    apply_exclude_routes(ctx, quiet=True)
    apply_static_routes(ctx, quiet=True)
    setup_policy_routing(ctx, quiet=True)


def reap_zombies() -> None:
    """Reap any terminated orphaned child processes when running as PID 1."""
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid <= 0:
                break
        except ChildProcessError:
            break


def shutdown(ctx: Ctx) -> None:
    if ctx.shut_down:
        return
    ctx.shut_down = True
    log("shutting down")
    proc, ctx.proc = ctx.proc, None
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    on_tunnel_down(ctx)
    remove_config(ctx)
    reap_zombies()


def main(argv: Sequence[str]) -> int:
    os.umask(0o077)
    if os.getuid() != 0:
        log("ERROR: this container must run as root")
        return 1
    if argv:
        os.execvp(argv[0], list(argv))
    try:
        cfg = Config.from_env(dict(os.environ))
    except FatalError as exc:
        log(f"ERROR: {exc}")
        return 1

    ctx = Ctx(cfg=cfg, runner=Runner())

    def handle_signal(_signum: int, _frame: object) -> None:
        ctx.request_stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        refresh_credentials(ctx)
        ctx.uplink_dev, ctx.uplink_gw = detect_uplink(ctx.runner)
        ctx.lan_iface = cfg.lan_iface or ctx.uplink_dev or "eth0"
        ctx.dns_resolvers = read_ipv4_nameservers()
        log(f"uplink is {ctx.uplink_dev} via {ctx.uplink_gw or '<direct route>'}")

        create_ppp_device(ctx)
        enable_forwarding(ctx)
        pin_dns_routes(ctx)
        if cfg.dns_servers:
            try:
                with (
                    open("/etc/resolv.conf", "rb") as src,
                    open(ctx.original_resolv_file, "wb") as dst,
                ):
                    dst.write(src.read())
            except OSError:
                raise FatalError("could not save the original /etc/resolv.conf")

        if is_on(cfg.firewall_enabled):
            select_backends(ctx)
            setup_firewall(ctx)
        else:
            warn("killswitch firewall is disabled")

        # Resolve through the configured DNS exceptions only after the
        # killswitch is closed. Then insert the scoped control exception.
        pin_server_routes(ctx)
        if ctx.stopping:
            return 0
        if is_on(cfg.firewall_enabled):
            allow_vpn_control(ctx)
            setup_policy_routing(ctx)

        while not ctx.stopping:
            refresh_credentials(ctx)
            write_config(ctx)
            cmd = ["openfortivpn", "-c", cfg.config_file] + shlex.split(cfg.extra_args)
            user = cfg.user or "<no user>"
            log(f"connecting to {cfg.host}:{cfg.port} as {user}")
            proc = subprocess.Popen(cmd)
            ctx.proc = proc
            last_reconcile = 0.0
            while proc.poll() is None and not ctx.stopping:
                iface = current_ppp_iface(ctx.runner)
                up = bool(iface and iface_has_ipv4(ctx.runner, iface))
                if up and ctx.configured_iface != iface:
                    ctx.configured_iface = iface or ""
                    on_tunnel_up(ctx, ctx.configured_iface)
                elif not up and ctx.configured_iface:
                    ctx.configured_iface = ""
                    on_tunnel_down(ctx)
                now = time.monotonic()
                if up and now - last_reconcile >= RECONCILE_INTERVAL:
                    last_reconcile = now
                    reconcile(ctx)
                ctx.stop_event.wait(MONITOR_INTERVAL)
            if ctx.stopping:
                break
            rc = proc.poll()
            ctx.proc = None
            on_tunnel_down(ctx)
            ctx.configured_iface = ""
            reap_zombies()
            log(
                f"openfortivpn exited (rc={rc}), reconnecting in {cfg.reconnect_delay}s"
            )
            ctx.stop_event.wait(cfg.reconnect_delay)
    except FatalError as exc:
        log(f"ERROR: {exc}")
        return 1
    finally:
        shutdown(ctx)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
