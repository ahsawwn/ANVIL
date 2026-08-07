import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from config.settings import (
    PROXYCHAINS_CONF_PATH,
    TOR_CONTROL_PASSWORD,
    TOR_CONTROL_PORT,
    TOR_HOST,
    TOR_SOCKS_PORT,
)

logger = logging.getLogger(__name__)


class ProxyManager:
    def __init__(self) -> None:
        self._controller = None

    def is_tor_running(self) -> bool:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", "tor"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        try:
            result = subprocess.run(
                ["pgrep", "-x", "tor"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def start_tor(self) -> bool:
        try:
            subprocess.run(
                ["sudo", "systemctl", "start", "tor"],
                capture_output=True,
                timeout=30,
            )
            return self.is_tor_running()
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.error("Could not start Tor: %s", exc)
            return False

    def ensure_tor(self) -> bool:
        if self.is_tor_running():
            return True
        logger.info("Tor not running; attempting to start it")
        return self.start_tor()

    def renew_circuit(self) -> tuple[bool, str]:
        try:
            from stem import Signal
            from stem.control import Controller

            with Controller.from_port(
                address=TOR_HOST, port=TOR_CONTROL_PORT
            ) as controller:
                controller.authenticate(password=TOR_CONTROL_PASSWORD)
                controller.signal(Signal.NEWNYM)
            return True, "Tor circuit renewed (NEWNYM sent)."
        except Exception as exc:
            logger.warning("Circuit renewal failed: %s", exc)
            return False, f"Circuit renewal failed: {exc}"

    def build_proxychains_conf(self, socks5: Optional[str] = None) -> Path:
        host, port = TOR_HOST, TOR_SOCKS_PORT
        if socks5:
            parsed = re.search(r"([\d.:a-fA-F]+)\s*[:]\s*(\d{2,5})", socks5)
            if parsed:
                host, port = parsed.group(1), int(parsed.group(2))
            else:
                space = re.search(r"(\S+)\s+(\d{2,5})\s*$", socks5)
                if space:
                    host, port = space.group(1), int(space.group(2))
        conf = (
            "# Anvil auto-generated proxychains config\n"
            "strict_chain\n"
            "proxy_dns\n"
            "remote_dns_subnet 224\n"
            "tcp_read_time_out 15000\n"
            "tcp_connect_time_out 8000\n"
            "[ProxyList]\n"
            f"socks5 {host} {port}\n"
        )
        PROXYCHAINS_CONF_PATH.write_text(conf, encoding="utf-8")
        logger.info("Wrote proxychains config to %s", PROXYCHAINS_CONF_PATH)
        return PROXYCHAINS_CONF_PATH

    def proxychains_bin(self) -> Optional[str]:
        return shutil.which("proxychains4") or shutil.which("proxychains")

    @staticmethod
    def public_ip() -> str:
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "8", "https://check.torproject.org/api/ip"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            match = re.search(r'"IP"\s*:\s*"([^"]+)"', result.stdout)
            return match.group(1) if match else "unknown"
        except Exception as exc:
            logger.debug("Public IP lookup failed: %s", exc)
            return "unknown"
