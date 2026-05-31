from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from astro.intel.cve_correlator import CVECorrelator, _parse_nvd_response


SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-12345",
                "descriptions": [
                    {"lang": "en", "value": "A critical vulnerability in Apache httpd"}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {
                        "description": [
                            {"lang": "en", "value": "CWE-79"},
                        ]
                    }
                ],
            }
        },
        {
            "cve": {
                "id": "CVE-2023-67890",
                "descriptions": [
                    {"lang": "en", "value": "A medium severity issue"}
                ],
                "metrics": {},
                "weaknesses": [],
            }
        },
    ]
}


class TestBuildCpe:
    def test_basic_cpe_format(self):
        correlator = CVECorrelator()
        cpe = correlator.build_cpe("apache", "httpd", "2.4.49")
        assert cpe == "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*"

    def test_normalizes_spaces_to_underscores(self):
        correlator = CVECorrelator()
        cpe = correlator.build_cpe("Open SSH", "SSH Server", "8.9")
        assert cpe == "cpe:2.3:a:open_ssh:ssh_server:8.9:*:*:*:*:*:*:*"

    def test_lowercases_vendor_and_product(self):
        correlator = CVECorrelator()
        cpe = correlator.build_cpe("Apache", "HTTPD", "2.4")
        assert "apache" in cpe
        assert "httpd" in cpe


class TestParseNvdResponse:
    def test_extracts_cve_ids(self):
        cves = _parse_nvd_response(SAMPLE_NVD_RESPONSE, "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*")
        ids = [c["id"] for c in cves]
        assert "CVE-2023-12345" in ids
        assert "CVE-2023-67890" in ids

    def test_extracts_cvss_score(self):
        cves = _parse_nvd_response(SAMPLE_NVD_RESPONSE, "cpe:test")
        cve1 = next(c for c in cves if c["id"] == "CVE-2023-12345")
        assert cve1["cvss_score"] == 9.8
        assert cve1["cvss_severity"] == "CRITICAL"

    def test_handles_missing_cvss(self):
        cves = _parse_nvd_response(SAMPLE_NVD_RESPONSE, "cpe:test")
        cve2 = next(c for c in cves if c["id"] == "CVE-2023-67890")
        assert cve2["cvss_score"] is None
        assert cve2["cvss_severity"] is None

    def test_extracts_cwes(self):
        cves = _parse_nvd_response(SAMPLE_NVD_RESPONSE, "cpe:test")
        cve1 = next(c for c in cves if c["id"] == "CVE-2023-12345")
        assert "CWE-79" in cve1["cwes"]

    def test_extracts_description(self):
        cves = _parse_nvd_response(SAMPLE_NVD_RESPONSE, "cpe:test")
        cve1 = next(c for c in cves if c["id"] == "CVE-2023-12345")
        assert "Apache httpd" in cve1["description"]

    def test_includes_cpe(self):
        cpe = "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*"
        cves = _parse_nvd_response(SAMPLE_NVD_RESPONSE, cpe)
        assert all(c["cpe"] == cpe for c in cves)

    def test_empty_vulnerabilities(self):
        cves = _parse_nvd_response({"vulnerabilities": []}, "cpe:test")
        assert cves == []


class TestLookupCves:
    async def test_caches_results(self):
        correlator = CVECorrelator()
        mock_response = MagicMock()
        mock_response.json.return_value = SAMPLE_NVD_RESPONSE
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result1 = await correlator.lookup_cves("apache", "httpd", "2.4.49")
            result2 = await correlator.lookup_cves("apache", "httpd", "2.4.49")

        assert len(result1) == 2
        assert result1 == result2
        mock_client.get.assert_called_once()

    async def test_returns_empty_on_error(self):
        correlator = CVECorrelator()

        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Connection error")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await correlator.lookup_cves("apache", "httpd", "2.4.49")

        assert result == []


class TestCorrelateFromNmap:
    async def test_enriches_with_host_and_port(self):
        correlator = CVECorrelator()
        mock_response = MagicMock()
        mock_response.json.return_value = SAMPLE_NVD_RESPONSE
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        parsed_nmap = {
            "hosts": [
                {
                    "address": "10.10.10.1",
                    "ports": [
                        {"port": 80, "service": "http", "version": "Apache/2.4.49"},
                    ],
                }
            ]
        }

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await correlator.correlate_from_nmap(parsed_nmap)

        assert len(results) > 0
        assert results[0]["host"] == "10.10.10.1"
        assert results[0]["port"] == 80

    async def test_skips_ports_without_version(self):
        correlator = CVECorrelator()
        parsed_nmap = {
            "hosts": [
                {
                    "address": "10.10.10.1",
                    "ports": [
                        {"port": 80, "service": "http", "version": ""},
                    ],
                }
            ]
        }
        results = await correlator.correlate_from_nmap(parsed_nmap)
        assert results == []
