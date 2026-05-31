"""CVE correlation engine using the NVD REST API v2."""
from __future__ import annotations

from typing import Any, Optional

import httpx
import structlog

logger = structlog.get_logger()


class CVECorrelator:
    """Correlates discovered services/versions with known CVEs via NVD API."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_db: Optional[Any] = None,
    ) -> None:
        self.api_key = api_key  # NVD API key for higher rate limits
        self.cache_db = cache_db  # Optional EngagementManager for persistent caching
        self._cache: dict[str, list[dict[str, Any]]] = {}

    def build_cpe(self, vendor: str, product: str, version: str) -> str:
        """Build CPE 2.3 string from service info."""
        vendor = vendor.lower().replace(" ", "_")
        product = product.lower().replace(" ", "_")
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    async def lookup_cves(
        self,
        vendor: str,
        product: str,
        version: str,
    ) -> list[dict[str, Any]]:
        """Query NVD API for CVEs matching the given service.

        Returns a list of CVE dicts with id, description, cvss_score,
        cvss_severity, cwes, and cpe fields.  Returns [] on failure.
        """
        cache_key = f"{vendor}:{product}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        cpe = self.build_cpe(vendor, product, version)
        params: dict[str, Any] = {"cpeName": cpe, "resultsPerPage": 20}
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(self.NVD_API_BASE, params=params, headers=headers)
                response.raise_for_status()
                data: dict[str, Any] = response.json()

            cves = _parse_nvd_response(data, cpe)
            self._cache[cache_key] = cves
            logger.info("cve_lookup_complete", cpe=cpe, count=len(cves))
            return cves

        except Exception as e:
            logger.error("cve_lookup_failed", cpe=cpe, error=str(e))
            return []

    async def correlate_from_nmap(
        self, parsed_nmap: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Extract services from parsed nmap output and look up CVEs.

        Expects parsed_nmap to have shape:
            {"hosts": [{"address": str, "ports": [{"port": int,
                        "service": str, "version": str}]}]}
        """
        all_cves: list[dict[str, Any]] = []
        for host in parsed_nmap.get("hosts", []):
            for port in host.get("ports", []):
                service: str = port.get("service", "")
                version: str = port.get("version", "")
                if not service or not version:
                    continue
                vendor = service.split("/")[0] if "/" in service else service
                product = service.split("/")[-1] if "/" in service else service
                cves = await self.lookup_cves(vendor, product, version)
                for cve in cves:
                    enriched = dict(cve)
                    enriched["host"] = host.get("address", "")
                    enriched["port"] = port.get("port", 0)
                    enriched["service"] = service
                    enriched["service_version"] = version
                    all_cves.append(enriched)
        return all_cves


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _parse_nvd_response(
    data: dict[str, Any], cpe: str
) -> list[dict[str, Any]]:
    """Extract a normalised CVE list from a raw NVD REST API v2 payload."""
    cves: list[dict[str, Any]] = []
    for vuln in data.get("vulnerabilities", []):
        cve_data: dict[str, Any] = vuln.get("cve", {})
        cve_id: str = cve_data.get("id", "")

        metrics: dict[str, Any] = cve_data.get("metrics", {})
        cvss_v31: list[dict[str, Any]] = metrics.get("cvssMetricV31", [])
        cvss_score: Optional[float] = (
            cvss_v31[0].get("cvssData", {}).get("baseScore") if cvss_v31 else None
        )
        cvss_severity: Optional[str] = (
            cvss_v31[0].get("cvssData", {}).get("baseSeverity") if cvss_v31 else None
        )

        descriptions: list[dict[str, Any]] = cve_data.get("descriptions", [])
        description: str = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )

        cwes: list[str] = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("value", "").startswith("CWE-"):
                    cwes.append(desc["value"])

        cves.append(
            {
                "id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cwes": cwes,
                "cpe": cpe,
            }
        )
    return cves
