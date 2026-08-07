from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Port:
    port_id: int
    protocol: str = "tcp"
    state: str = "unknown"
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    scripts: dict = field(default_factory=dict)

    @property
    def version_text(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        return " ".join(parts).strip()

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    def script_summary(self) -> str:
        lines = []
        for script_id, output in self.scripts.items():
            lines.append(f"- {script_id}: {output}")
        return "\n".join(lines)


@dataclass
class Vulnerability:
    name: str
    cve_id: str = "N/A"
    exploit_db_id: str = "N/A"
    metasploit_module: str = "N/A"
    risk: str = "Unknown"
    remediation: str = ""
    port: Optional[int] = None
    service: str = ""

    @property
    def is_critical(self) -> bool:
        return self.risk.lower() == "critical"


RISK_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


@dataclass
class ScanReport:
    target: str
    hostname: str = ""
    status: str = "unknown"
    ports: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    started: str = ""
    finished: str = ""
    profile: str = ""
    use_tor: bool = False
    command: str = ""
    xml_path: str = ""

    def add_port(self, port: Port) -> None:
        self.ports.append(port)

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        self.vulnerabilities.append(vuln)

    @property
    def open_ports(self) -> list:
        return [p for p in self.ports if p.is_open]

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.is_critical)

    def vulnerabilities_for(self, port: Port) -> list:
        return [
            v
            for v in self.vulnerabilities
            if v.port == port.port_id and v.service == port.service
        ]

    def highest_risk_for(self, port: Port) -> str:
        risks = [v.risk for v in self.vulnerabilities_for(port)]
        if not risks:
            return "Low"
        return max(risks, key=lambda r: RISK_RANK.get(r.lower(), 0))

    @property
    def summary(self) -> str:
        vulns = len(self.vulnerabilities)
        return (
            f"{self.target}: {len(self.open_ports)} open ports, "
            f"{vulns} vulnerabilities ({self.critical_count} critical)"
        )
