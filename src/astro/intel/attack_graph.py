"""Attack graph builder using networkx."""
from __future__ import annotations

from typing import Any

import networkx as nx
import structlog

logger = structlog.get_logger()


class AttackGraphBuilder:
    """Builds exploitability graphs from engagement findings."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()

    def add_host(
        self, address: str, os: str = "", status: str = "up"
    ) -> None:
        """Add a host node to the graph."""
        self.graph.add_node(address, type="host", os=os, status=status)

    def add_service(
        self,
        host: str,
        port: int,
        service: str,
        version: str = "",
    ) -> None:
        """Add a service node and link it to its host."""
        service_id = f"{host}:{port}"
        self.graph.add_node(
            service_id,
            type="service",
            port=port,
            service=service,
            version=version,
        )
        self.graph.add_edge(host, service_id, relation="exposes")

    def add_vulnerability(
        self,
        service_id: str,
        cve_id: str,
        cvss_score: float = 0.0,
        description: str = "",
    ) -> None:
        """Add a CVE vulnerability node and link it to the affected service."""
        self.graph.add_node(
            cve_id,
            type="vulnerability",
            cvss_score=cvss_score,
            description=description,
        )
        self.graph.add_edge(service_id, cve_id, relation="vulnerable_to")

    def add_finding(
        self,
        source: str,
        target: str,
        finding_type: str,
        details: str = "",
    ) -> None:
        """Add a generic directed finding edge between two existing nodes."""
        self.graph.add_edge(source, target, relation=finding_type, details=details)

    def build_from_nmap(self, parsed_nmap: dict[str, Any]) -> None:
        """Populate graph from parsed nmap output.

        Expects parsed_nmap to have shape:
            {"hosts": [{"address": str, "os": str, "status": str,
                        "ports": [{"port": int, "service": str, "version": str}]}]}
        """
        for host in parsed_nmap.get("hosts", []):
            addr: str = host.get("address", "")
            if not addr:
                continue
            self.add_host(
                addr,
                os=host.get("os", ""),
                status=host.get("status", "up"),
            )
            for port in host.get("ports", []):
                self.add_service(
                    addr,
                    port["port"],
                    port.get("service", ""),
                    port.get("version", ""),
                )

    def build_from_cves(self, cves: list[dict[str, Any]]) -> None:
        """Add CVE nodes and edges from CVECorrelator results.

        Each CVE dict must have host, port, id, cvss_score, and description.
        """
        for cve in cves:
            service_id = f"{cve.get('host', '')}:{cve.get('port', 0)}"
            if service_id not in self.graph:
                continue
            self.add_vulnerability(
                service_id,
                cve["id"],
                cve.get("cvss_score") or 0.0,
                cve.get("description", ""),
            )

    def get_attack_paths(
        self, min_cvss: float = 7.0, cutoff: int = 8
    ) -> list[list[str]]:
        """Find paths through the graph leading to high-severity CVE nodes.

        Args:
            min_cvss: Minimum CVSS score threshold (inclusive).
            cutoff: Maximum path length to avoid exponential blowup on dense
                    graphs.

        Returns:
            A list of node-id lists, each representing one attack path from a
            host to a qualifying vulnerability.
        """
        paths: list[list[str]] = []
        vuln_nodes = [
            n
            for n, d in self.graph.nodes(data=True)
            if d.get("type") == "vulnerability"
            and (d.get("cvss_score") or 0.0) >= min_cvss
        ]
        host_nodes = [
            n
            for n, d in self.graph.nodes(data=True)
            if d.get("type") == "host"
        ]

        for host in host_nodes:
            for vuln in vuln_nodes:
                try:
                    for path in nx.all_simple_paths(
                        self.graph, host, vuln, cutoff=cutoff
                    ):
                        paths.append(path)
                except nx.NetworkXNoPath:
                    continue
                except nx.NodeNotFound:
                    continue
        return paths

    def to_json(self) -> dict[str, Any]:
        """Serialise graph to a JSON-serialisable dict for LLM consumption."""
        nodes = self.graph.nodes(data=True)
        edges = self.graph.edges(data=True)
        return {
            "nodes": [{"id": n, **d} for n, d in nodes],
            "edges": [{"source": u, "target": v, **d} for u, v, d in edges],
            "stats": {
                "hosts": sum(
                    1 for _, d in nodes if d.get("type") == "host"
                ),
                "services": sum(
                    1 for _, d in nodes if d.get("type") == "service"
                ),
                "vulnerabilities": sum(
                    1 for _, d in nodes if d.get("type") == "vulnerability"
                ),
            },
        }
