"""Remediation recommendation engine."""
from __future__ import annotations

from typing import Any, Optional

# ---------------------------------------------------------------------------
# Static remediation knowledge base
# ---------------------------------------------------------------------------

# Outer key: finding type.  Inner key: port number (str) or "general"/"default".
REMEDIATION_DB: dict[str, dict[str, str]] = {
    "open-port": {
        "general": (
            "Review whether this port needs to be externally accessible. "
            "Close unnecessary ports via firewall rules."
        ),
        "22": (
            "Disable password authentication. Use key-based SSH only. "
            "Consider changing the default port."
        ),
        "23": "Telnet is unencrypted. Replace with SSH immediately.",
        "80": (
            "Ensure HTTP redirects to HTTPS. Review web server configuration "
            "for security headers."
        ),
        "443": (
            "Verify TLS configuration. Use TLS 1.2+ only. "
            "Check certificate validity."
        ),
        "445": (
            "Restrict SMB access to trusted networks. Disable SMBv1. "
            "Apply latest patches."
        ),
        "3306": (
            "MySQL should not be exposed externally. "
            "Use firewall rules to restrict access."
        ),
        "3389": (
            "RDP should be behind VPN. Enable NLA. Apply rate limiting."
        ),
    },
    "cve": {
        "default": (
            "Apply the vendor patch for this CVE. "
            "Check the NVD entry for specific remediation guidance."
        ),
    },
    "weak-credentials": {
        "default": (
            "Enforce strong password policy. "
            "Implement account lockout after failed attempts. "
            "Use MFA where possible."
        ),
    },
}


class RemediationEngine:
    """Provides remediation recommendations for security findings."""

    def recommend(
        self,
        finding_type: str,
        details: Optional[dict[str, Any]] = None,
    ) -> str:
        """Return a remediation recommendation string for the given finding.

        Args:
            finding_type: One of ``"open-port"``, ``"cve"``,
                          ``"weak-credentials"``, or any arbitrary string.
            details:       Optional context dict; for ``"open-port"`` pass
                           ``{"port": <int>}``.

        Returns:
            A human-readable remediation recommendation.
        """
        details = details or {}

        if finding_type == "open-port":
            port = str(details.get("port", ""))
            specific: Optional[str] = REMEDIATION_DB["open-port"].get(port)
            general: str = REMEDIATION_DB["open-port"]["general"]
            return f"{specific}\n\n{general}" if specific else general

        if finding_type == "cve":
            return REMEDIATION_DB["cve"]["default"]

        if finding_type == "weak-credentials":
            return REMEDIATION_DB["weak-credentials"]["default"]

        return "Review the finding and apply appropriate security controls."

    def enrich_findings(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Add remediation recommendations to a list of findings in-place.

        Mutates each finding dict by adding a ``"remediation"`` key.

        Returns:
            The same list with remediation fields populated.
        """
        for finding in findings:
            parsed: dict[str, Any] = finding.get("parsed_output") or {}
            tool: str = finding.get("tool", "")

            if tool == "nmap" and parsed:
                recommendations: list[dict[str, Any]] = []
                for host in parsed.get("hosts", []):
                    for port in host.get("ports", []):
                        if port.get("state") == "open":
                            rec = self.recommend(
                                "open-port", {"port": port["port"]}
                            )
                            recommendations.append(
                                {
                                    "port": port["port"],
                                    "remediation": rec,
                                }
                            )
                finding["remediation"] = recommendations

            elif tool == "hydra":
                finding["remediation"] = [
                    {"remediation": self.recommend("weak-credentials")}
                ]

        return findings
