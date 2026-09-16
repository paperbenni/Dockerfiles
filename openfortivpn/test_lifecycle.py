"""Tunnel reconciliation and process-lifecycle tests."""

import os
import unittest

from ofv_entrypoint import lifecycle, network
from test_support import FakeRunner, ctx_with


class TestReconcile(unittest.TestCase):
    def test_full_tunnel_reapplies_hijacked_default(self):
        routes = {
            ("ip", "-4", "route", "show", "default"): (
                0,
                "default via 192.168.1.1 dev eth0\n",
            ),
        }
        ctx = ctx_with(runner=FakeRunner(routes))
        ctx.configured_iface = "ppp0"
        lifecycle.reconcile(ctx)
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertTrue(any("ip route replace default dev ppp0" in c for c in flat))

    def test_noop_when_default_correct(self):
        routes = {
            ("ip", "-4", "route", "show", "default"): (
                0,
                "default dev ppp0 scope link\n",
            ),
        }
        ctx = ctx_with(runner=FakeRunner(routes))
        ctx.configured_iface = "ppp0"
        lifecycle.reconcile(ctx)
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertFalse(any("replace default dev ppp0" in c for c in flat))

    def test_split_mode_leaves_server_routes_alone(self):
        routes = {
            ("ip", "-4", "route", "show", "default"): (
                0,
                "default dev ppp0 scope link\n",
            ),
        }
        ctx = ctx_with(runner=FakeRunner(routes))
        ctx.cfg.full_tunnel = "off"
        ctx.configured_iface = "ppp0"
        lifecycle.reconcile(ctx)
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertFalse(
            any("replace default" in c and "table 200" not in c for c in flat)
        )


class TestLifecycle(unittest.TestCase):
    def test_request_stop_sets_event_and_flag(self):
        ctx = ctx_with()
        self.assertFalse(ctx.stopping)
        self.assertFalse(ctx.stop_event.is_set())
        ctx.request_stop()
        self.assertTrue(ctx.stopping)
        self.assertTrue(ctx.stop_event.is_set())

    def test_shutdown_idempotent(self):
        ctx = ctx_with()
        lifecycle.shutdown(ctx)
        self.assertTrue(ctx.shut_down)
        lifecycle.shutdown(ctx)
        self.assertTrue(ctx.shut_down)

    def test_shutdown_terminates_running_process(self):
        class FakeProc:
            def __init__(self):
                self.terminated = False
                self.waited = False

            def poll(self):
                return 0 if self.terminated else None

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                self.waited = True
                return 0

        ctx = ctx_with()
        proc = FakeProc()
        ctx.proc = proc  # type: ignore[assignment]
        lifecycle.shutdown(ctx)
        self.assertTrue(proc.terminated)
        self.assertTrue(proc.waited)
        self.assertIsNone(ctx.proc)

    def test_remove_config_unlinks_file(self):
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"secret")
            temp_path = tf.name
        ctx = ctx_with()
        ctx.cfg.config_file = temp_path
        self.assertTrue(os.path.exists(temp_path))
        network.remove_config(ctx)
        self.assertFalse(os.path.exists(temp_path))
