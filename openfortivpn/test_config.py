"""Configuration and rendering tests."""

import unittest

from ofv_entrypoint import config, runtime


class TestPredicates(unittest.TestCase):
    def test_is_on(self):
        for yes in ("on", "ON", "1", "yes", "YES", "true", " True "):
            self.assertTrue(runtime.is_on(yes), yes)
        for no in ("off", "0", "no", "false", "", "2"):
            self.assertFalse(runtime.is_on(no), no)

    def test_split_list(self):
        self.assertEqual(runtime.split_list("a,b c,,d"), ["a", "b", "c", "d"])
        self.assertEqual(runtime.split_list(""), [])
        self.assertEqual(runtime.split_list("100.64.0.0/10"), ["100.64.0.0/10"])


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = config.Config.from_env(
            {"VPN_HOST": "h", "VPN_USER": "u", "VPN_PASSWORD": "p"}
        )
        self.assertEqual(cfg.port, 443)
        self.assertEqual(cfg.exclude_routes, ["100.64.0.0/10"])
        self.assertEqual(cfg.set_routes, "1")
        self.assertEqual(cfg.full_tunnel, "on")

    def test_host_required(self):
        with self.assertRaises(runtime.FatalError):
            config.Config.from_env({})

    def test_bad_port(self):
        for bad in ("0", "65536", "abc", "443x", ""):
            with self.assertRaises(runtime.FatalError, msg=bad):
                config.Config.from_env({"VPN_HOST": "h", "VPN_PORT": bad})

    def test_bad_delay(self):
        with self.assertRaises(runtime.FatalError):
            config.Config.from_env({"VPN_HOST": "h", "VPN_RECONNECT_DELAY": "-1"})

    def test_secret_exclusion(self):
        with self.assertRaises(runtime.FatalError):
            config.Config.from_env(
                {"VPN_HOST": "h", "VPN_PASSWORD": "a", "VPN_PASSWORD_FILE": "/x"}
            )
        with self.assertRaises(runtime.FatalError):
            config.Config.from_env(
                {"VPN_HOST": "h", "VPN_OTP": "a", "VPN_OTP_FILE": "/x"}
            )

    def test_bad_cidr(self):
        with self.assertRaises(runtime.FatalError):
            config.Config.from_env({"VPN_HOST": "h", "VPN_ROUTES": "999.1.1.0/24"})

    def test_cidrs_are_normalized(self):
        cfg = config.Config.from_env(
            {
                "VPN_HOST": "h",
                "VPN_ROUTES": "192.0.2.9/24",
                "VPN_EXCLUDE_ROUTES": "198.51.100.7/24",
            }
        )
        self.assertEqual(cfg.routes, ["192.0.2.0/24"])
        self.assertEqual(cfg.exclude_routes, ["198.51.100.0/24"])

    def test_ipv6_cidr_is_rejected(self):
        with self.assertRaises(runtime.FatalError):
            config.Config.from_env({"VPN_HOST": "h", "VPN_ROUTES": "2001:db8::/32"})

    def test_bad_set_routes(self):
        with self.assertRaises(runtime.FatalError):
            config.Config.from_env({"VPN_HOST": "h", "VPN_SET_ROUTES": "2"})


class TestRenderConfig(unittest.TestCase):
    def test_full(self):
        cfg = config.Config(
            host="h",
            port=8443,
            user="u",
            password="p",
            otp="123",
            realm="r",
            trusted_cert="ab",
            set_routes="0",
        )
        text = config.render_config(cfg)
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
        text = config.render_config(config.Config(host="h"))
        self.assertNotIn("password", text)
        self.assertNotIn("username", text)
        self.assertIn("set-routes = 1", text)
