"""Tunnel reconciliation and process shutdown behavior."""

from __future__ import annotations

import os
import subprocess

from .firewall import setup_policy_routing
from .network import (
    apply_exclude_routes,
    apply_static_routes,
    default_route_dev,
    on_tunnel_down,
    remove_config,
)
from .runtime import Ctx, is_on, log, warn


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
