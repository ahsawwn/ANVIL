import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from config.settings import VAULT_ROOT
from models.scan_result import Port, ScanReport, Vulnerability

logger = logging.getLogger(__name__)


class MarkdownGenerator:
    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else VAULT_ROOT
        self.targets_dir = self.root / "Targets"
        self.services_dir = self.root / "Services"
        self.attacks_dir = self.root / "Attacks"
        for directory in (self.root, self.targets_dir, self.services_dir, self.attacks_dir):
            directory.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _slug(text: str, fallback: str = "item") -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-.")
        return cleaned or fallback

    @staticmethod
    def _safe_target(target: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", target)

    @staticmethod
    def _escape_cell(text: str) -> str:
        return (text or "").replace("|", "\\|").replace("\n", " ").strip()

    def generate(self, report: ScanReport) -> None:
        try:
            if not report.open_ports:
                logger.info("No open ports for %s; skipping vault write", report.target)
                return

            target_slug = self._safe_target(report.target)
            report_file = self.targets_dir / f"{target_slug}.md"
            report_file.write_text(self._target_md(report), encoding="utf-8")

            for port in report.open_ports:
                service_slug = self._slug(
                    f"{target_slug}_{port.port_id}_{port.service}",
                    fallback=f"{target_slug}_{port.port_id}",
                )
                service_file = self.services_dir / f"{service_slug}.md"
                vulns = report.vulnerabilities_for(port)
                service_file.write_text(self._service_md(report, port, vulns), encoding="utf-8")

                for vuln in vulns:
                    attack_slug = self._slug(vuln.name, fallback="attack")
                    attack_file = self.attacks_dir / f"{attack_slug}.md"
                    if not attack_file.exists():
                        attack_file.write_text(self._attack_md(vuln), encoding="utf-8")

            self._generate_index()
            logger.info("Vault updated for %s", report.target)
        except Exception as exc:
            logger.error("Markdown generation failed: %s", exc)

    def _target_md(self, report: ScanReport) -> str:
        lines = [
            f"# Target: {report.target}",
            "",
            f"- **Scan Date**: {report.started}",
            f"- **Profile**: {report.profile or 'Custom'}",
            f"- **Anonymity**: {'Tor / Proxy' if report.use_tor else 'Direct'}",
            f"- **Hostname**: {report.hostname or 'N/A'}",
            f"- **Status**: {report.status}",
            f"- **Critical Vulnerabilities**: {report.critical_count}",
            f"- **Total Vulnerabilities**: {len(report.vulnerabilities)}",
            "",
            "## Open Ports",
            "",
            "| Port | Protocol | Service | Version | State |",
            "|---|---|---|---|---|",
        ]
        for port in report.open_ports:
            lines.append(
                f"| {port.port_id} | {port.protocol} | {self._escape_cell(port.service)} | "
                f"{self._escape_cell(port.version_text)} | {port.state} |"
            )
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        for port in report.open_ports:
            service_slug = self._slug(
                f"{self._safe_target(report.target)}_{port.port_id}_{port.service}",
                fallback=f"{self._safe_target(report.target)}_{port.port_id}",
            )
            lines.append(f"- [[Services/{service_slug}]]")
        return "\n".join(lines) + "\n"

    def _service_md(self, report: ScanReport, port: Port, vulns: list) -> str:
        lines = [
            f"# {port.service.upper() or 'SERVICE'} ({report.target}:{port.port_id})",
            "",
            f"- **Target**: {report.target}",
            f"- **Port**: {port.port_id}/{port.protocol}",
            f"- **State**: {port.state}",
            f"- **Product**: {port.product or 'N/A'}",
            f"- **Version**: {port.version or 'N/A'}",
            f"- **Extra**: {port.extra_info or 'N/A'}",
            "",
            "## Scripts",
            "",
        ]
        if port.scripts:
            for script_id, output in port.scripts.items():
                lines.append(f"- **{script_id}**: {self._escape_cell(output)}")
        else:
            lines.append("- None detected")
        lines.append("")

        if vulns:
            lines.append("## Vulnerabilities")
            lines.append("")
            for vuln in vulns:
                attack_slug = self._slug(vuln.name, fallback="attack")
                lines.append(f"![[Attacks/{attack_slug}.md]]")
            lines.append("")
        return "\n".join(lines) + "\n"

    def _attack_md(self, vuln: Vulnerability) -> str:
        msf = vuln.metasploit_module or "N/A"
        return (
            f"# {vuln.name}\n\n"
            f"**Port**: {vuln.port or 'N/A'}\n"
            f"**CVE**: {vuln.cve_id or 'N/A'}\n"
            f"**Exploit-DB**: {vuln.exploit_db_id or 'N/A'}\n"
            f"**Risk**: {vuln.risk}\n"
            f"**MSF Command**: `{msf}`\n\n"
            f"## Remediation\n\n{vuln.remediation or 'Investigate and patch.'}\n"
        )

    def _generate_index(self) -> None:
        rows = []
        for path in sorted(self.targets_dir.glob("*.md")):
            rows.append((path.stem, path.stat().st_mtime))
        if not rows:
            return
        lines = [
            "# Anvil Scan Index",
            "",
            "> Obsidian vault of all Anvil scan results.",
            "",
            "## Scans",
            "",
            "| Target | Last Modified |",
            "|---|---|",
        ]
        for stem, mtime in rows:
            date = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
            lines.append(f"| [[Targets/{stem}]] | {date} |")
        index_path = self.root / "Index.md"
        index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def all_markdown_files(self) -> list[Path]:
        return sorted(self.root.rglob("*.md"))
