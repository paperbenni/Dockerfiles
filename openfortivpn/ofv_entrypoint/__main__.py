"""Executable orchestration and reconnect loop."""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
import time
from collections.abc import Sequence

from .config import Config
from .firewall import (
    allow_vpn_control,
    select_backends,
    setup_firewall,
    setup_policy_routing,
)
from .lifecycle import reap_zombies, reconcile, shutdown
from .network import (
    create_ppp_device,
    current_ppp_iface,
    detect_uplink,
    enable_forwarding,
    iface_has_ipv4,
    on_tunnel_down,
    on_tunnel_up,
    pin_dns_routes,
    pin_server_routes,
    read_ipv4_nameservers,
    refresh_credentials,
    write_config,
)
from .runtime import (
    MONITOR_INTERVAL,
    RECONCILE_INTERVAL,
    Ctx,
    FatalError,
    Runner,
    is_on,
    log,
    warn,
)


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
