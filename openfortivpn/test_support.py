"""Shared fakes and fixtures for entrypoint unit tests."""

import subprocess

from ofv_entrypoint.config import Config
from ofv_entrypoint.runtime import Ctx, Runner


class FakeRunner(Runner):
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
    cfg = Config(host="vpn.example.com", user="u", password="p")
    ctx = Ctx(
        cfg=cfg,
        runner=FakeRunner(),
        uplink_dev="eth0",
        uplink_gw="192.168.1.1",
        lan_iface="eth0",
    )
    for name, value in overrides.items():
        setattr(ctx, name, value)
    return ctx


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
