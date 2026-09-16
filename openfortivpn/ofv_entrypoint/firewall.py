"""IPv4/IPv6 killswitch construction and inbound policy routing."""

from __future__ import annotations

import ipaddress
import os

from .network import connected_subnets, via_uplink
from .runtime import POLICY_MARK, POLICY_TABLE, Ctx, FatalError, log, warn


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
