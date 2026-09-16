#!/usr/bin/env python3
"""Unit tests for docker-entrypoint.py. Stdlib only, no root needed.

Run:  python3 -m unittest test_entrypoint -v
"""

import importlib.util
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load_entrypoint():
    spec = importlib.util.spec_from_file_location(
        "entrypoint", os.path.join(HERE, "docker-entrypoint.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["entrypoint"] = module
    spec.loader.exec_module(module)
    return module


e = load_entrypoint()


class FakeRunner(e.Runner):
    """Scripted outputs + recorded commands."""

    def __init__(self, outputs=None, fail_on=(), missing=()):
        # outputs: {tuple(argv): (returncode, stdout)}
        # fail_on: substrings; any call containing one fails with rc=1
        # missing: binary names reported as absent by has()
        self.outputs = outputs or {}
        self.fail_on = tuple(fail_on)
        self.missing = set(missing)
        self.calls: list[list[str]] = []

    def run(self, argv):
        self.calls.append(list(argv))
        if tuple(argv) in self.outputs:
            rc, out = self.outputs[tuple(argv)]
        elif any(mark in " ".join(argv) for mark in self.fail_on):
            rc, out = 1, ""
        else:
            rc, out = 0, ""
        return subprocess.CompletedProcess(list(argv), rc, out, "")

    def has(self, cmd):
        return cmd not in self.missing


def ctx_with(**overrides):
    cfg = e.Config(host="vpn.example.com", user="u", password="p")
    params = {
        "cfg": cfg,
        "runner": FakeRunner(),
        "uplink_dev": "eth0",
        "uplink_gw": "192.168.1.1",
        "lan_iface": "eth0",
    }
    params.update(overrides)
    return e.Ctx(**params)


BUSYBOX_NSLOOKUP = """\
Server:\t\t100.100.100.100
Address:\t100.100.100.100:53

Non-authoritative answer:
Name:\tfortivpn.example.com
Address 1: 132.230.121.17

Non-authoritative answer:
Name:\tfortivpn.example.com
Address 1: 132.230.121.17
"""


class TestPredicates(unittest.TestCase):
    def test_is_on(self):
        for yes in ("on", "ON", "1", "yes", "YES", "true", " True "):
            self.assertTrue(e.is_on(yes), yes)
        for no in ("off", "0", "no", "false", "", "2"):
            self.assertFalse(e.is_on(no), no)

    def test_split_list(self):
        self.assertEqual(e.split_list("a,b c,,d"), ["a", "b", "c", "d"])
        self.assertEqual(e.split_list(""), [])
        self.assertEqual(e.split_list("100.64.0.0/10"), ["100.64.0.0/10"])


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = e.Config.from_env({"VPN_HOST": "h", "VPN_USER": "u", "VPN_PASSWORD": "p"})
        self.assertEqual(cfg.port, 443)
        self.assertEqual(cfg.exclude_routes, ["100.64.0.0/10"])
        self.assertEqual(cfg.set_routes, "1")
        self.assertEqual(cfg.full_tunnel, "on")

    def test_host_required(self):
        with self.assertRaises(e.FatalError):
            e.Config.from_env({})

    def test_bad_port(self):
        for bad in ("0", "65536", "abc", "443x", ""):
            with self.assertRaises(e.FatalError, msg=bad):
                e.Config.from_env({"VPN_HOST": "h", "VPN_PORT": bad})

    def test_bad_delay(self):
        with self.assertRaises(e.FatalError):
            e.Config.from_env({"VPN_HOST": "h", "VPN_RECONNECT_DELAY": "-1"})

    def test_secret_exclusion(self):
        with self.assertRaises(e.FatalError):
            e.Config.from_env(
                {"VPN_HOST": "h", "VPN_PASSWORD": "a", "VPN_PASSWORD_FILE": "/x"}
            )
        with self.assertRaises(e.FatalError):
            e.Config.from_env({"VPN_HOST": "h", "VPN_OTP": "a", "VPN_OTP_FILE": "/x"})

    def test_bad_cidr(self):
        with self.assertRaises(e.FatalError):
            e.Config.from_env({"VPN_HOST": "h", "VPN_ROUTES": "999.1.1.0/24"})

    def test_cidrs_are_normalized(self):
        cfg = e.Config.from_env(
            {
                "VPN_HOST": "h",
                "VPN_ROUTES": "192.0.2.9/24",
                "VPN_EXCLUDE_ROUTES": "198.51.100.7/24",
            }
        )
        self.assertEqual(cfg.routes, ["192.0.2.0/24"])
        self.assertEqual(cfg.exclude_routes, ["198.51.100.0/24"])

    def test_ipv6_cidr_is_rejected(self):
        with self.assertRaises(e.FatalError):
            e.Config.from_env({"VPN_HOST": "h", "VPN_ROUTES": "2001:db8::/32"})

    def test_bad_set_routes(self):
        with self.assertRaises(e.FatalError):
            e.Config.from_env({"VPN_HOST": "h", "VPN_SET_ROUTES": "2"})


class TestRenderConfig(unittest.TestCase):
    def test_full(self):
        cfg = e.Config(
            host="h",
            port=8443,
            user="u",
            password="p",
            otp="123",
            realm="r",
            trusted_cert="ab",
            set_routes="0",
        )
        text = e.render_config(cfg)
        for line in (
            "host = h",
            "port = 8443",
            "username = u",
            "password = p",
            "otp = 123",
            "realm = r",
            "trusted-cert = ab",
            "set-routes = 0",
            "persistent = 0",
        ):
            self.assertIn(line, text)
        self.assertNotIn("user-cert", text)  # empty optionals omitted

    def test_minimal_has_no_secrets(self):
        text = e.render_config(e.Config(host="h"))
        self.assertNotIn("password", text)
        self.assertNotIn("username", text)
        self.assertIn("set-routes = 1", text)


class TestResolve(unittest.TestCase):
    def test_literal_ip(self):
        self.assertEqual(e.resolve_ipv4(FakeRunner(), "1.2.3.4"), ["1.2.3.4"])

    def test_busybox_output_ignores_server_line(self):
        r = FakeRunner({("nslookup", "h"): (0, BUSYBOX_NSLOOKUP)})
        # 100.100.100.100:53 must NOT leak in (port suffix filtered out)
        self.assertEqual(e.resolve_ipv4(r, "h"), ["132.230.121.17"])

    def test_empty(self):
        r = FakeRunner({("nslookup", "h"): (0, "Server: 1.1.1.1\n")})
        self.assertEqual(e.resolve_ipv4(r, "h"), [])


class TestRoutes(unittest.TestCase):
    def test_parse_default_with_gw(self):
        dev, gw = e.parse_default_route("default via 192.168.112.1 dev eth0 proto dhcp")
        self.assertEqual((dev, gw), ("eth0", "192.168.112.1"))

    def test_parse_default_direct(self):
        dev, gw = e.parse_default_route("default dev ppp0 scope link")
        self.assertEqual((dev, gw), ("ppp0", ""))

    def test_detect_uplink(self):
        r = FakeRunner(
            {
                ("ip", "-4", "route", "show", "default"): (
                    0,
                    "default via 10.0.0.1 dev eth9\n",
                )
            }
        )
        self.assertEqual(e.detect_uplink(r), ("eth9", "10.0.0.1"))

    def test_detect_uplink_missing(self):
        with self.assertRaises(e.FatalError):
            e.detect_uplink(FakeRunner())

    def test_ppp_iface(self):
        out = "1: lo: <LOOPBACK>\n12: ppp0: <POINTOPOINT>\n"
        r = FakeRunner({("ip", "-o", "link", "show"): (0, out)})
        self.assertEqual(e.current_ppp_iface(r), "ppp0")

    def test_no_ppp_iface(self):
        r = FakeRunner(
            {
                ("ip", "-o", "link", "show"): (
                    0,
                    "1: lo: <LOOPBACK>\n2: eth0: <BROADCAST>\n",
                )
            }
        )
        self.assertIsNone(e.current_ppp_iface(r))

    def test_connected_subnets(self):
        out = (
            "192.168.112.0/20 dev eth0 proto kernel scope link src 192.168.112.2\n"
            "default via 192.168.112.1 dev eth0\n"
        )
        r = FakeRunner({("ip", "-4", "route", "show", "dev", "eth0"): (0, out)})
        self.assertEqual(e.connected_subnets(r, "eth0"), ["192.168.112.0/20"])

    def test_read_ipv4_nameservers(self):
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            tf.write(
                "nameserver 192.0.2.53\n"
                "nameserver 2001:db8::53\n"
                "search example.test\n"
                "nameserver 192.0.2.53\n"
            )
            path = tf.name
        try:
            self.assertEqual(e.read_ipv4_nameservers(path), ["192.0.2.53"])
        finally:
            os.remove(path)


class TestFirewallBuild(unittest.TestCase):
    def test_output_chain_rules(self):
        ctx = ctx_with(server_ips=["9.9.9.9"])
        e.ensure_chain(ctx, "filter", "OFV_OUTPUT")
        e.ensure_rule(ctx, "filter", "OFV_OUTPUT", ["-o", "ppp+", "-j", "ACCEPT"], "x")
        e.ensure_rule(
            ctx,
            "filter",
            "OFV_OUTPUT",
            [
                "-o",
                "eth0",
                "-d",
                "9.9.9.9",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "ACCEPT",
            ],
            "x",
        )
        e.ensure_rule(ctx, "filter", "OFV_OUTPUT", ["-j", "DROP"], "x")
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertTrue(any("iptables -t filter -N OFV_OUTPUT" in c for c in flat))
        self.assertTrue(any("-o ppp+ -j ACCEPT" in c for c in flat))
        self.assertTrue(
            any("-d 9.9.9.9 -p tcp --dport 443 -j ACCEPT" in c for c in flat)
        )
        self.assertTrue(flat[-1].endswith("OFV_OUTPUT -j DROP"))

    def test_idempotent_rule_add(self):
        # -C succeeds -> no -A issued
        r = FakeRunner(
            {("iptables", "-t", "filter", "-C", "CH", "-j", "DROP"): (0, "")}
        )
        ctx = ctx_with(runner=r)
        e.ensure_rule(ctx, "filter", "CH", ["-j", "DROP"], "x")
        self.assertEqual(len(r.calls), 1)

    def test_full_firewall_wires_jumps(self):
        routes = {
            ("ip", "-4", "route", "show", "dev", "eth0"): (
                0,
                "192.168.112.0/20 dev eth0 proto kernel scope link src 192.168.112.2\n",
            ),
        }
        ctx = ctx_with(
            runner=FakeRunner(routes, fail_on=["-C"]), server_ips=["9.9.9.9"]
        )
        e.setup_firewall(ctx, has_ipv6=False)
        flat = [" ".join(c) for c in ctx.runner.calls]
        for jump in (
            "filter -I OUTPUT 1 -j OFV_OUTPUT",
            "filter -I INPUT 1 -j OFV_INPUT",
            "filter -I FORWARD 1 -j OFV_FORWARD",
        ):
            self.assertTrue(any(jump in c for c in flat), jump)
        # published ports via DNAT match, no port enumeration
        self.assertTrue(any("--ctstate DNAT -j ACCEPT" in c for c in flat))
        # auto-detected docker subnet allowed inbound
        self.assertTrue(any("-s 192.168.112.0/20 -j ACCEPT" in c for c in flat))
        output_rules = [c for c in flat if "filter -A OFV_OUTPUT" in c]
        established_output_rules = [
            c for c in output_rules if "--ctstate ESTABLISHED,RELATED" in c
        ]
        self.assertTrue(established_output_rules)
        self.assertTrue(
            all("-m mark --mark 0x1" in c for c in established_output_rules)
        )
        self.assertTrue(
            any(
                "-o eth0 -m mark --mark 0x1 -m conntrack "
                "--ctstate ESTABLISHED,RELATED -j ACCEPT" in c
                for c in output_rules
            )
        )

    def test_vpn_control_uses_uplink_dev(self):
        ctx = ctx_with(uplink_dev="eth0", lan_iface="eth1", server_ips=["9.9.9.9"])
        e.setup_firewall(ctx, has_ipv6=False)
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertTrue(
            any("-o eth0 -d 9.9.9.9 -p tcp --dport 443 -j ACCEPT" in c for c in flat)
        )

    def test_direct_dns_is_limited_to_resolver_and_port(self):
        ctx = ctx_with(dns_resolvers=["192.0.2.53"])
        e.setup_firewall(ctx, has_ipv6=False)
        flat = [" ".join(c) for c in ctx.runner.calls]
        for protocol in ("udp", "tcp"):
            self.assertTrue(
                any(
                    f"-o eth0 -d 192.0.2.53 -p {protocol} --dport 53 -j ACCEPT" in c
                    for c in flat
                )
            )

    def test_dns_routes_are_pinned_to_uplink(self):
        ctx = ctx_with(dns_resolvers=["127.0.0.11", "192.0.2.53"])
        e.pin_dns_routes(ctx)
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertFalse(any("127.0.0.11" in c for c in flat))
        self.assertTrue(
            any(
                "ip route replace 192.0.2.53/32 via 192.168.1.1 dev eth0" in c
                for c in flat
            )
        )

    def test_late_vpn_control_rule_is_inserted_before_drop(self):
        ctx = ctx_with(runner=FakeRunner(fail_on=["-C"]), server_ips=["9.9.9.9"])
        e.allow_vpn_control(ctx)
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertTrue(
            any(
                "iptables -t filter -I OFV_OUTPUT 1 -o eth0 -d 9.9.9.9" in c
                for c in flat
            )
        )


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
        e.reconcile(ctx)
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
        e.reconcile(ctx)
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
        e.reconcile(ctx)
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertFalse(
            any("replace default" in c and "table 200" not in c for c in flat)
        )


class TestBackends(unittest.TestCase):
    def test_prefers_nft_backend(self):
        ctx = ctx_with()
        e.select_backends(ctx)
        self.assertEqual((ctx.ipt, ctx.ip6t), ("iptables", "ip6tables"))

    def test_falls_back_to_legacy(self):
        outputs = {
            ("iptables", "-t", "nat", "-S", "DOCKER_OUTPUT"): (1, ""),
            ("iptables-legacy", "-t", "nat", "-S", "DOCKER_OUTPUT"): (0, ""),
        }
        ctx = ctx_with(runner=FakeRunner(outputs))
        e.select_backends(ctx)
        self.assertEqual((ctx.ipt, ctx.ip6t), ("iptables-legacy", "ip6tables-legacy"))

    def test_dies_without_backend(self):
        ctx = ctx_with(runner=FakeRunner(fail_on=["iptables"]))
        with self.assertRaises(e.FatalError):
            e.select_backends(ctx)

    def test_ipv6_skipped_when_absent(self):
        ctx = ctx_with()
        e.setup_ipv6_firewall(ctx, has_ipv6=False)  # no commands, no error
        self.assertEqual(ctx.runner.calls, [])

    def test_ipv6_dies_without_binary(self):
        # Regression: PATH must not leak into unit tests.
        ctx = ctx_with(runner=FakeRunner(missing=["ip6tables"]))
        with self.assertRaises(e.FatalError):
            e.setup_ipv6_firewall(ctx, has_ipv6=True)


class TestPolicyRouting(unittest.TestCase):
    def test_rule_skipped_when_already_present(self):
        rules = "0: from all lookup local\n100: from all fwmark 0x1 lookup 200\n"
        r = FakeRunner({("ip", "rule", "show"): (0, rules)})
        ctx = ctx_with(runner=r)
        self.assertTrue(e.setup_policy_routing(ctx, quiet=True))
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertFalse(any("ip rule add" in c for c in flat))

    def test_rule_added_when_separate_lines_match_subsets(self):
        # Regression: multi-line check must not falsely believe the rule exists.
        rules = (
            "0: from all lookup local\n"
            "50: from all fwmark 0x1 lookup 100\n"
            "60: from all lookup 200\n"
        )
        r = FakeRunner({("ip", "rule", "show"): (0, rules)})
        ctx = ctx_with(runner=r)
        self.assertTrue(e.setup_policy_routing(ctx, quiet=True))
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertTrue(any("ip rule add fwmark 0x1 table 200" in c for c in flat))

    def test_ensure_chain_exists_does_not_flush(self):
        r = FakeRunner({("iptables", "-t", "mangle", "-S", "OFV_PREROUTING"): (0, "")})
        ctx = ctx_with(runner=r)
        self.assertTrue(e.ensure_chain_exists(ctx, "mangle", "OFV_PREROUTING"))
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertFalse(any("-F OFV_PREROUTING" in c for c in flat))


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
        e.shutdown(ctx)
        self.assertTrue(ctx.shut_down)
        e.shutdown(ctx)
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
        e.shutdown(ctx)
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
        e.remove_config(ctx)
        self.assertFalse(os.path.exists(temp_path))


class TestPinRoutes(unittest.TestCase):
    def test_pin_server_routes_retries(self):
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tf:
            hosts_path = tf.name
        try:
            r = FakeRunner(
                {
                    ("nslookup", "vpn.example.com"): (0, BUSYBOX_NSLOOKUP),
                }
            )
            ctx = ctx_with(runner=r, hosts_file=hosts_path)
            e.pin_server_routes(ctx, max_retries=2, retry_delay=0.01)
            self.assertEqual(ctx.server_ips, ["132.230.121.17"])
            with open(hosts_path) as fh:
                self.assertIn("132.230.121.17\tvpn.example.com", fh.read())
        finally:
            if os.path.exists(hosts_path):
                os.remove(hosts_path)

    def test_pin_server_routes_clean_exit_when_stopping(self):
        r = FakeRunner()
        ctx = ctx_with(runner=r)
        ctx.request_stop()
        e.pin_server_routes(ctx, max_retries=3, retry_delay=0.01)
        self.assertEqual(ctx.server_ips, [])


if __name__ == "__main__":
    unittest.main()
