"""Shared runtime constants, command runner, logging, and mutable context."""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Config

POLICY_TABLE = "200"
POLICY_MARK = "0x1"
RECONCILE_INTERVAL = 10.0
MONITOR_INTERVAL = 2.0
IPV4_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
PORT_RE = re.compile(r"^[0-9]+$")
DELAY_RE = re.compile(r"^[0-9]+([.][0-9]+)?$")


def log(msg: str) -> None:
    stamp = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"{stamp} [openfortivpn] {msg}", flush=True)


def warn(msg: str) -> None:
    log(f"WARN: {msg}")


class FatalError(Exception):
    """Fatal startup/runtime error. main() logs it and exits 1."""


def is_on(value: str) -> bool:
    return value.strip().lower() in ("on", "1", "yes", "true")


def split_list(value: str) -> list[str]:
    """Split comma- and/or space-separated env var into clean tokens."""
    return [tok for tok in value.replace(",", " ").split() if tok]


class Runner:
    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(list(argv), capture_output=True, text=True, check=False)

    def ok(self, argv: Sequence[str]) -> bool:
        return self.run(argv).returncode == 0

    def has(self, cmd: str) -> bool:
        """Whether a binary exists on PATH (mockable for hermetic tests)."""
        return shutil.which(cmd) is not None

    def out(self, argv: Sequence[str]) -> str:
        proc = self.run(argv)
        return proc.stdout if proc.returncode == 0 else ""


@dataclass
class Ctx:
    cfg: Config
    runner: Runner
    uplink_dev: str = ""
    uplink_gw: str = ""
    lan_iface: str = ""
    server_ips: list[str] = field(default_factory=list)
    dns_resolvers: list[str] = field(default_factory=list)
    ipt: str = "iptables"
    ip6t: str = "ip6tables"
    stopping: bool = False
    shut_down: bool = False
    stop_event: threading.Event = field(default_factory=threading.Event)
    configured_iface: str = ""
    proc: subprocess.Popen | None = None
    original_resolv_file: str = "/run/openfortivpn-resolv.conf"
    hosts_file: str = "/etc/hosts"

    def request_stop(self) -> None:
        self.stopping = True
        self.stop_event.set()
