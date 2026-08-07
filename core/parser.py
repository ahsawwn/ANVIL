import logging
import re
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

from config.settings import SCAN_OUTPUT_PATH, ScanProfile
from models.scan_result import Port, ScanReport

logger = logging.getLogger(__name__)


def parse_scan_xml(
    path: Path,
    target: str,
    profile: ScanProfile,
    use_tor: bool = False,
) -> ScanReport:
    try:
        return _parse_python_nmap(path, target, profile, use_tor)
    except Exception as exc:
        logger.warning("python-nmap parse failed (%s); using ElementTree fallback", exc)
        return _parse_element_tree(path, target, profile, use_tor)


def _new_report(target: str, profile: ScanProfile, use_tor: bool) -> ScanReport:
    return ScanReport(
        target=target,
        profile=profile.label,
        use_tor=use_tor,
        started=datetime.now().isoformat(timespec="seconds"),
        xml_path=str(SCAN_OUTPUT_PATH),
    )


def _port_from_dict(port_id: str, protocol: str, info: dict) -> Port:
    scripts = {k: v for k, v in info.get("script", {}).items() if isinstance(v, str)}
    return Port(
        port_id=int(port_id),
        protocol=protocol,
        state=info.get("state", "unknown"),
        service=info.get("name", ""),
        product=info.get("product", ""),
        version=info.get("version", ""),
        extra_info=info.get("extrainfo", ""),
        scripts=scripts,
    )


def _parse_python_nmap(path: Path, target: str, profile: ScanProfile, use_tor: bool) -> ScanReport:
    import nmap

    scanner = nmap.PortScanner()
    scanner.parse(path.read_text(errors="replace"))

    report = _new_report(target, profile, use_tor)
    for host in scanner.all_hosts():
        host_data = scanner[host]
        names = [h.get("name", "") for h in host_data.get("hostnames", [])]
        report.hostname = next((n for n in names if n), report.hostname)
        status = host_data.get("status", {}).get("state", "unknown")
        report.status = report.status if report.status != "unknown" else status

        for protocol in ("tcp", "udp"):
            ports = host_data.get(protocol, {})
            for port_id, info in ports.items():
                report.add_port(_port_from_dict(port_id, protocol, info))
        break
    return report


def _parse_element_tree(path: Path, target: str, profile: ScanProfile, use_tor: bool) -> ScanReport:
    report = _new_report(target, profile, use_tor)
    tree = ElementTree.parse(path)
    root = tree.getroot()
    for host in root.findall("host"):
        status_el = host.find("status")
        report.status = status_el.get("state", "unknown") if status_el is not None else "unknown"
        hostnames = host.findall("hostnames/hostname")
        if hostnames:
            report.hostname = hostnames[0].get("name", "")

        for port in host.findall("ports/port"):
            port_id = port.get("portid", "")
            protocol = port.get("protocol", "tcp")
            state_el = port.find("state")
            service_el = port.find("service")
            scripts = {}
            for script in port.findall("script"):
                scripts[script.get("id", "")] = script.get("output", "")
            if hostnames:
                hostscripts = host.findall("hostscript/script")
                for script in hostscripts:
                    scripts[script.get("id", "")] = script.get("output", "")
            report.add_port(
                Port(
                    port_id=int(port_id) if port_id.isdigit() else -1,
                    protocol=protocol,
                    state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                    service=service_el.get("name", "") if service_el is not None else "",
                    product=service_el.get("product", "") if service_el is not None else "",
                    version=service_el.get("version", "") if service_el is not None else "",
                    extra_info=service_el.get("extrainfo", "") if service_el is not None else "",
                    scripts=scripts,
                )
            )
        break
    return report
