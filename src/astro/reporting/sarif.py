"""SARIF 2.1.0 report generator for engagement findings."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional


# Severity mapping from CVSS severity strings to SARIF level strings.
_CVSS_TO_SARIF_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


class SARIFGenerator:
    """Generate SARIF 2.1.0 reports from engagement findings."""

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main"
        "/sarif-2.1/schema/sarif-schema-2.1.0.json"
    )

    def __init__(
        self,
        tool_name: str = "project-astro",
        tool_version: str = "2.0.0",
    ) -> None:
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(
        self,
        findings: list[dict[str, Any]],
        cves: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        """Generate a SARIF report from findings and optional CVE data.

        Args:
            findings: List of tool finding dicts.  Each dict must have at
                      minimum ``tool``, ``target``, and optionally
                      ``parsed_output`` (the structured parser output).
            cves:     Optional CVE correlation results from CVECorrelator.

        Returns:
            A SARIF 2.1.0-compliant dict.
        """
        results: list[dict[str, Any]] = []
        rules: dict[str, dict[str, Any]] = {}

        for finding in findings:
            tool: str = finding.get("tool", "unknown")
            target: str = finding.get("target", "unknown")
            parsed: dict[str, Any] = finding.get("parsed_output") or {}

            if tool == "nmap" and parsed:
                _process_nmap_finding(parsed, target, rules, results)

        if cves:
            _process_cves(cves, rules, results)

        return {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                }
            ],
        }

    def to_json(
        self,
        findings: list[dict[str, Any]],
        cves: Optional[list[dict[str, Any]]] = None,
        indent: int = 2,
    ) -> str:
        """Serialise the SARIF report to a JSON string."""
        return json.dumps(self.generate(findings, cves), indent=indent)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _process_nmap_finding(
    parsed: dict[str, Any],
    target: str,
    rules: dict[str, dict[str, Any]],
    results: list[dict[str, Any]],
) -> None:
    """Convert parsed nmap output into SARIF rules and results in-place."""
    for host in parsed.get("hosts", []):
        address: str = host.get("address", target)
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            port_num: int = port["port"]
            protocol: str = port.get("protocol", "tcp")
            service: str = port.get("service", "unknown")
            version: str = port.get("version", "")
            rule_id = f"open-port-{port_num}"

            rules[rule_id] = {
                "id": rule_id,
                "name": f"OpenPort{port_num}",
                "shortDescription": {
                    "text": f"Open port {port_num}/{protocol}"
                },
                "defaultConfiguration": {"level": "note"},
            }
            message_text = (
                f"Port {port_num} is open running {service} {version}".strip()
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "note",
                    "message": {"text": message_text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": address}
                            }
                        }
                    ],
                }
            )


def _process_cves(
    cves: list[dict[str, Any]],
    rules: dict[str, dict[str, Any]],
    results: list[dict[str, Any]],
) -> None:
    """Convert CVE correlation results into SARIF rules and results in-place."""
    for cve in cves:
        rule_id: str = cve["id"]
        severity: str = cve.get("cvss_severity") or "MEDIUM"
        level: str = _CVSS_TO_SARIF_LEVEL.get(severity, "warning")

        rules[rule_id] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": cve.get("description", "")[:200]},
            "defaultConfiguration": {"level": level},
            "properties": {
                "cvss_score": cve.get("cvss_score"),
                "cwes": cve.get("cwes", []),
            },
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": cve.get("description", "No description available")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": cve.get("host", "unknown")
                            }
                        }
                    }
                ],
            }
        )
