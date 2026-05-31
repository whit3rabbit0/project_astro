"""Nmap XML output parser using python-libnmap."""
from typing import Any

from astro.parsers.base import BaseParser


class NmapStructuredParser(BaseParser):
    """Parse nmap XML output into a structured host/port/service dict."""

    def parse(self, raw_output: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        """Conform to BaseParser interface. XML content expected in raw_output['xml_content']."""
        xml_content = raw_output.get("xml_content", "")
        if not xml_content:
            return None
        return self._parse_xml(xml_content)

    def parse_from_file(self, xml_path: str) -> dict[str, Any] | None:
        """Parse nmap XML from a file path. Used by NmapTool.execute()."""
        try:
            with open(xml_path, "r", encoding="utf-8") as fh:
                xml_content = fh.read()
        except OSError:
            return None
        if not xml_content.strip():
            return None
        return self._parse_xml(xml_content)

    def _parse_xml(self, xml_content: str) -> dict[str, Any] | None:
        try:
            from libnmap.parser import NmapParser as LibNmapParser  # type: ignore[import]
        except ImportError:
            return None

        try:
            report = LibNmapParser.parse_fromstring(xml_content)
        except Exception:
            return None

        hosts = []
        for host in report.hosts:
            ports = []
            for port in host.get_open_ports():
                port_num, protocol = port
                svc = host.get_service(port_num, protocol)
                ports.append({
                    "port": port_num,
                    "protocol": protocol,
                    "state": svc.state if svc else "open",
                    "service": svc.service if svc else "",
                    "version": svc.banner if svc else "",
                })
            hosts.append({
                "address": host.address,
                "status": host.status,
                "ports": ports,
                "os": host.os_class_probabilities() if hasattr(host, "os_class_probabilities") else [],
            })

        return {"hosts": hosts, "scan_info": report.scan_type if hasattr(report, "scan_type") else ""}
