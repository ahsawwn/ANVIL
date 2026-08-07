import json
import logging
import re
from pathlib import Path
from typing import Optional

from config.settings import RESOURCES_DIR
from models.scan_result import ScanReport, Vulnerability

logger = logging.getLogger(__name__)

SERVICE_ALIASES = {
    "https": "http",
    "ssl/http": "http",
    "ssl/https": "http",
    "http-alt": "http",
    "http-proxy": "http",
    "ms-wbt-server": "rdp",
    "netbios-ssn": "smb",
    "microsoft-ds": "smb",
    "hostmsgs": "smb",
    "domain": "dns",
    "snmptrap": "snmp",
    "postgres": "postgresql",
    "unknown": "unknown",
}

RISK_DEFAULT = "Unknown"


class AttackMapper:
    def __init__(self, db_path: Optional[Path] = None) -> None:
        path = Path(db_path) if db_path else RESOURCES_DIR / "attack_db.json"
        self.entries = self._load_db(path)

    @staticmethod
    def _load_db(path: Path) -> list:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                return data
            logger.error("attack_db.json must be a JSON list")
            return []
        except Exception as exc:
            logger.error("Failed to load attack database: %s", exc)
            return []

    @staticmethod
    def _matches_keyword(version_text: str, keyword: str) -> bool:
        if not keyword:
            return True
        patterns = [k.strip().lower() for k in keyword.split("|") if k.strip()]
        if not patterns:
            return True
        text = version_text.lower()
        return any(re.search(re.escape(p), text) for p in patterns)

    def _map_entry(self, port) -> list:
        service = port.service.strip().lower()
        alias = SERVICE_ALIASES.get(service, service)
        version_text = f"{port.product} {port.version}".strip()
        vulns = []
        for entry in self.entries:
            entry_service = entry.get("service", "").lower()
            entry_port = entry.get("port")
            if entry_service != alias:
                continue
            if entry_port is not None and entry_port != port.port_id:
                continue
            if not self._matches_keyword(version_text, entry.get("version_keyword", "")):
                continue
            for item in entry.get("vulnerabilities", []):
                vulns.append(
                    Vulnerability(
                        name=item.get("name", "Unknown"),
                        cve_id=item.get("cve", "N/A"),
                        exploit_db_id=str(item.get("exploit_db", "N/A")),
                        metasploit_module=item.get("msf_module", "N/A"),
                        risk=item.get("risk", RISK_DEFAULT),
                        remediation=item.get("remediation", ""),
                        port=port.port_id,
                        service=port.service,
                    )
                )
        return vulns

    def map(self, report: ScanReport) -> None:
        for port in report.open_ports:
            vulns = self._map_entry(port)
            for vuln in vulns:
                report.add_vulnerability(vuln)
            if not vulns:
                fallback = self._query_online(port.service, port.version_text)
                if fallback:
                    for vuln in fallback:
                        report.add_vulnerability(vuln)

    @staticmethod
    def _query_online(service: str, version: str) -> list:
        try:
            return _placeholder_online_lookup(service, version)
        except Exception as exc:
            logger.debug("Online lookup unavailable: %s", exc)
            return []


def _placeholder_online_lookup(service: str, version: str) -> list:
    logger.info(
        "No local DB match for %s %s; online API lookup is a placeholder. "
        "Integrate the Vulners/NVD API here for production use.",
        service,
        version,
    )
    return []


_mapper_instance: Optional[AttackMapper] = None


def get_mapper() -> AttackMapper:
    global _mapper_instance
    if _mapper_instance is None:
        _mapper_instance = AttackMapper()
    return _mapper_instance


def map_report(report: ScanReport) -> None:
    get_mapper().map(report)
