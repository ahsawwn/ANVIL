import logging
import os
import shlex
import shutil
import signal
import subprocess
from typing import Optional

from PySide6.QtCore import QObject, Signal

from config import settings
from config.settings import ScanProfile
from core.attack_mapper import map_report
from core.parser import parse_scan_xml
from models.scan_result import ScanReport, Vulnerability

logger = logging.getLogger(__name__)


def build_nmap_command(
    target: str,
    profile: ScanProfile,
    use_tor: bool = False,
    custom_proxy: Optional[str] = None,
) -> tuple[list, Optional[str]]:
    flags = profile.flags + shlex.split(settings.EXTRA_SCRIPTS)
    flags += ["-oX", str(settings.SCAN_OUTPUT_PATH)]

    nmap_bin = str(settings.NMAP_PATH)
    base = ([nmap_bin] if os.geteuid() == 0 else ["sudo", nmap_bin]) + flags + [target]

    warning = None
    if use_tor:
        proxychains = shutil.which("proxychains4") or shutil.which("proxychains")
        if proxychains:
            return (
                [proxychains, "-f", str(settings.PROXYCHAINS_CONF_PATH)] + base,
                None,
            )
        warning = "proxychains4 not found; falling back to a direct scan."

    return base, warning


class ScanWorker(QObject):
    output = Signal(str)
    finished = Signal(object)
    failed = Signal(str)
    critical_found = Signal(object)

    def __init__(
        self,
        target: str,
        profile: ScanProfile,
        use_tor: bool = False,
        custom_proxy: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.target = target
        self.profile = profile
        self.use_tor = use_tor
        self.custom_proxy = custom_proxy
        self._process: Optional[subprocess.Popen] = None
        self._stopped = False

    def run(self) -> None:
        try:
            cmd, warning = build_nmap_command(
                self.target, self.profile, self.use_tor, self.custom_proxy
            )
            self.output.emit("$ " + subprocess.list2cmdline(cmd))
            if warning:
                self.output.emit(f"[!] {warning}")

            env = os.environ.copy()
            env.setdefault("LC_ALL", "C")
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )

            assert self._process.stdout is not None
            for line in iter(self._process.stdout.readline, ""):
                if self._stopped:
                    break
                self.output.emit(line.rstrip("\n"))
            self._process.wait()

            if self._stopped:
                self.failed.emit("Scan stopped by user.")
                return
            if self._process.returncode != 0:
                self.failed.emit(f"Nmap exited with code {self._process.returncode}.")
                return

            report = parse_scan_xml(
                settings.SCAN_OUTPUT_PATH,
                self.target,
                self.profile,
                self.use_tor,
            )
            report.command = subprocess.list2cmdline(cmd)
            map_report(report)
            for vuln in report.vulnerabilities:
                if vuln.is_critical:
                    self.critical_found.emit(vuln)
            self.finished.emit(report)
        except Exception as exc:
            logger.exception("Scan failed")
            self.failed.emit(str(exc))

    def stop(self) -> None:
        self._stopped = True
        if self._process and self._process.poll() is None:
            try:
                self._process.send_signal(signal.SIGTERM)
                self.output.emit("\n[*] SIGTERM sent to Nmap.")
            except Exception as exc:
                logger.warning("Failed to terminate Nmap: %s", exc)
