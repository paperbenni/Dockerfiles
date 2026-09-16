"""Firewall backend, rule, and policy-routing tests."""

import unittest

from ofv_entrypoint import firewall, network, runtime
from test_support import FakeRunner, ctx_with


class TestFirewallBuild(unittest.TestCase):
    def test_output_chain_rules(self):
        ctx = ctx_with(server_ips=["9.9.9.9"])
        firewall.ensure_chain(ctx, "filter", "OFV_OUTPUT")
        firewall.ensure_rule(
            ctx, "filter", "OFV_OUTPUT", ["-o", "ppp+", "-j", "ACCEPT"], "x"
        )
        firewall.ensure_rule(
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
        firewall.ensure_rule(ctx, "filter", "OFV_OUTPUT", ["-j", "DROP"], "x")
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
        firewall.ensure_rule(ctx, "filter", "CH", ["-j", "DROP"], "x")
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
        firewall.setup_firewall(ctx, has_ipv6=False)
        flat = [" ".join(c) for c in ctx.runner.calls]
        for jump in (
            "filter -I OUTPUT 1 -j OFV_OUTPUT",
            "filter -I INPUT 1 -j OFV_INPUT",
            "filter -I FORWARD 1 -j OFV_FORWARD",
        ):
            self.assertTrue(any(jump in c for c in flat), jump)
        # Accept traffic addressed to the namespace's attached subnet. The
        # remote source may be LAN, Tailscale, or another routed network.
        self.assertTrue(any("-d 192.168.112.0/20 -j ACCEPT" in c for c in flat))
        self.assertFalse(any("--ctstate DNAT" in c for c in flat))
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
        firewall.setup_firewall(ctx, has_ipv6=False)
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertTrue(
            any("-o eth0 -d 9.9.9.9 -p tcp --dport 443 -j ACCEPT" in c for c in flat)
        )

    def test_direct_dns_is_limited_to_resolver_and_port(self):
        ctx = ctx_with(dns_resolvers=["192.0.2.53"])
        firewall.setup_firewall(ctx, has_ipv6=False)
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
        network.pin_dns_routes(ctx)
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
        firewall.allow_vpn_control(ctx)
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertTrue(
            any(
                "iptables -t filter -I OFV_OUTPUT 1 -o eth0 -d 9.9.9.9" in c
                for c in flat
            )
        )


class TestBackends(unittest.TestCase):
    def test_prefers_nft_backend(self):
        ctx = ctx_with()
        firewall.select_backends(ctx)
        self.assertEqual((ctx.ipt, ctx.ip6t), ("iptables", "ip6tables"))

    def test_falls_back_to_legacy(self):
        outputs = {
            ("iptables", "-t", "nat", "-S", "DOCKER_OUTPUT"): (1, ""),
            ("iptables-legacy", "-t", "nat", "-S", "DOCKER_OUTPUT"): (0, ""),
        }
        ctx = ctx_with(runner=FakeRunner(outputs))
        firewall.select_backends(ctx)
        self.assertEqual((ctx.ipt, ctx.ip6t), ("iptables-legacy", "ip6tables-legacy"))

    def test_dies_without_backend(self):
        ctx = ctx_with(runner=FakeRunner(fail_on=["iptables"]))
        with self.assertRaises(runtime.FatalError):
            firewall.select_backends(ctx)

    def test_ipv6_skipped_when_absent(self):
        ctx = ctx_with()
        firewall.setup_ipv6_firewall(ctx, has_ipv6=False)  # no commands, no error
        self.assertEqual(ctx.runner.calls, [])

    def test_ipv6_dies_without_binary(self):
        # Regression: PATH must not leak into unit tests.
        ctx = ctx_with(runner=FakeRunner(missing=["ip6tables"]))
        with self.assertRaises(runtime.FatalError):
            firewall.setup_ipv6_firewall(ctx, has_ipv6=True)


class TestPolicyRouting(unittest.TestCase):
    def test_rule_skipped_when_already_present(self):
        rules = "0: from all lookup local\n100: from all fwmark 0x1 lookup 200\n"
        r = FakeRunner({("ip", "rule", "show"): (0, rules)})
        ctx = ctx_with(runner=r)
        self.assertTrue(firewall.setup_policy_routing(ctx, quiet=True))
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
        self.assertTrue(firewall.setup_policy_routing(ctx, quiet=True))
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertTrue(any("ip rule add fwmark 0x1 table 200" in c for c in flat))

    def test_ensure_chain_exists_does_not_flush(self):
        r = FakeRunner({("iptables", "-t", "mangle", "-S", "OFV_PREROUTING"): (0, "")})
        ctx = ctx_with(runner=r)
        self.assertTrue(firewall.ensure_chain_exists(ctx, "mangle", "OFV_PREROUTING"))
        flat = [" ".join(c) for c in ctx.runner.calls]
        self.assertFalse(any("-F OFV_PREROUTING" in c for c in flat))
