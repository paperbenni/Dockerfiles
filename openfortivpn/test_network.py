"""Network discovery and route-management tests."""

import os
import unittest

from ofv_entrypoint import network, runtime
from test_support import BUSYBOX_NSLOOKUP, FakeRunner, ctx_with


class TestResolve(unittest.TestCase):
    def test_literal_ip(self):
        self.assertEqual(network.resolve_ipv4(FakeRunner(), "1.2.3.4"), ["1.2.3.4"])

    def test_busybox_output_ignores_server_line(self):
        r = FakeRunner({("nslookup", "h"): (0, BUSYBOX_NSLOOKUP)})
        # 100.100.100.100:53 must NOT leak in (port suffix filtered out)
        self.assertEqual(network.resolve_ipv4(r, "h"), ["132.230.121.17"])

    def test_empty(self):
        r = FakeRunner({("nslookup", "h"): (0, "Server: 1.1.1.1\n")})
        self.assertEqual(network.resolve_ipv4(r, "h"), [])


class TestRoutes(unittest.TestCase):
    def test_parse_default_with_gw(self):
        dev, gw = network.parse_default_route(
            "default via 192.168.112.1 dev eth0 proto dhcp"
        )
        self.assertEqual((dev, gw), ("eth0", "192.168.112.1"))

    def test_parse_default_direct(self):
        dev, gw = network.parse_default_route("default dev ppp0 scope link")
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
        self.assertEqual(network.detect_uplink(r), ("eth9", "10.0.0.1"))

    def test_detect_uplink_missing(self):
        with self.assertRaises(runtime.FatalError):
            network.detect_uplink(FakeRunner())

    def test_ppp_iface(self):
        out = "1: lo: <LOOPBACK>\n12: ppp0: <POINTOPOINT>\n"
        r = FakeRunner({("ip", "-o", "link", "show"): (0, out)})
        self.assertEqual(network.current_ppp_iface(r), "ppp0")

    def test_no_ppp_iface(self):
        r = FakeRunner(
            {
                ("ip", "-o", "link", "show"): (
                    0,
                    "1: lo: <LOOPBACK>\n2: eth0: <BROADCAST>\n",
                )
            }
        )
        self.assertIsNone(network.current_ppp_iface(r))

    def test_connected_subnets(self):
        out = (
            "192.168.112.0/20 dev eth0 proto kernel scope link src 192.168.112.2\n"
            "default via 192.168.112.1 dev eth0\n"
        )
        r = FakeRunner({("ip", "-4", "route", "show", "dev", "eth0"): (0, out)})
        self.assertEqual(network.connected_subnets(r, "eth0"), ["192.168.112.0/20"])

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
            self.assertEqual(network.read_ipv4_nameservers(path), ["192.0.2.53"])
        finally:
            os.remove(path)


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
            network.pin_server_routes(ctx, max_retries=2, retry_delay=0.01)
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
        network.pin_server_routes(ctx, max_retries=3, retry_delay=0.01)
        self.assertEqual(ctx.server_ips, [])
