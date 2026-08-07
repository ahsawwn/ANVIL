import os
import pwd
from enum import Enum
from pathlib import Path

APP_NAME = "Anvil"
APP_VERSION = "1.0.0"


def _owner_home() -> Path:
    for var in ("SUDO_USER", "PKEXEC_UID"):
        value = os.environ.get(var)
        if not value:
            continue
        try:
            if var == "SUDO_USER":
                return Path(pwd.getpwnam(value).pw_dir)
            return Path(pwd.getpwuid(int(value)).pw_dir)
        except (KeyError, ValueError, ImportError, OSError):
            continue
    return Path.home()


OWNER_HOME = _owner_home()

NMAP_PATH = Path("/usr/bin/nmap")
SCAN_OUTPUT_PATH = Path("/tmp/anvil_scan.xml")
PROXYCHAINS_CONF_PATH = Path("/tmp/anvil_proxy.conf")

TOR_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_CONTROL_PASSWORD = ""

VAULT_ROOT = OWNER_HOME / "anvil_vault"
DB_PATH = OWNER_HOME / ".anvil" / "anvil.db"
LOG_PATH = OWNER_HOME / ".anvil" / "anvil.log"
RESOURCES_DIR = Path(__file__).resolve().parent.parent / "resources"

EXTRA_SCRIPTS = "--script=default,vuln,exploit,brute,auth"

PROFILE_FLAGS = {
    "quick": ["-T4", "-F"],
    "full": ["-sS", "-sV", "-O", "-A", "-p-", "--min-rate=1000"],
    "stealth": ["-sS", "-f", "--data-length", "200", "-D", "RND:10", "--max-retries", "0"],
    "udp": ["-sU", "--top-ports", "200"],
}


class ScanProfile(Enum):
    QUICK = ("quick", "Quick")
    FULL = ("full", "Full")
    STEALTH = ("stealth", "Stealth")
    UDP = ("udp", "UDP")

    @property
    def key(self) -> str:
        return self.value[0]

    @property
    def label(self) -> str:
        return self.value[1]

    @property
    def flags(self) -> list:
        return list(PROFILE_FLAGS[self.key])
