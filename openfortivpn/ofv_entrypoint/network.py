"""Network discovery, route management, and tunnel transitions."""

from __future__ import annotations

import ipaddress
import os
import socket

from .config import render_config
from .runtime import IPV4_RE, Ctx, FatalError, Runner, is_on, log, split_list, warn


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
