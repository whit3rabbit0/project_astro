import pytest

from astro.reporting.remediation import RemediationEngine


@pytest.fixture
def engine():
    return RemediationEngine()


class TestRecommendOpenPort:
    def test_port_22_ssh_recommendation(self, engine):
        rec = engine.recommend("open-port", {"port": 22})
        assert "key-based SSH" in rec
        assert "password authentication" in rec.lower() or "Disable" in rec

    def test_port_23_telnet_recommendation(self, engine):
        rec = engine.recommend("open-port", {"port": 23})
        assert "Telnet" in rec
        assert "SSH" in rec

    def test_port_80_http_recommendation(self, engine):
        rec = engine.recommend("open-port", {"port": 80})
        assert "HTTPS" in rec

    def test_port_443_tls_recommendation(self, engine):
        rec = engine.recommend("open-port", {"port": 443})
        assert "TLS" in rec

    def test_port_445_smb_recommendation(self, engine):
        rec = engine.recommend("open-port", {"port": 445})
        assert "SMB" in rec

    def test_port_3306_mysql_recommendation(self, engine):
        rec = engine.recommend("open-port", {"port": 3306})
        assert "MySQL" in rec

    def test_port_3389_rdp_recommendation(self, engine):
        rec = engine.recommend("open-port", {"port": 3389})
        assert "RDP" in rec or "VPN" in rec

    def test_unknown_port_returns_general(self, engine):
        rec = engine.recommend("open-port", {"port": 9999})
        assert "firewall" in rec.lower() or "Close" in rec

    def test_no_port_in_details_returns_general(self, engine):
        rec = engine.recommend("open-port", {})
        assert "firewall" in rec.lower() or "Close" in rec


class TestRecommendCve:
    def test_cve_recommendation(self, engine):
        rec = engine.recommend("cve")
        assert "patch" in rec.lower() or "vendor" in rec.lower()


class TestRecommendWeakCredentials:
    def test_weak_credentials_recommendation(self, engine):
        rec = engine.recommend("weak-credentials")
        assert "password" in rec.lower()
        assert "MFA" in rec


class TestRecommendUnknownType:
    def test_unknown_type_returns_generic(self, engine):
        rec = engine.recommend("something-else")
        assert "security controls" in rec.lower()


class TestEnrichFindings:
    def test_enriches_nmap_findings(self, engine):
        findings = [
            {
                "tool": "nmap",
                "target": "10.10.10.1",
                "parsed_output": {
                    "hosts": [
                        {
                            "address": "10.10.10.1",
                            "ports": [
                                {"port": 22, "state": "open"},
                                {"port": 80, "state": "open"},
                            ],
                        }
                    ]
                },
            }
        ]
        enriched = engine.enrich_findings(findings)
        assert len(enriched) == 1
        assert "remediation" in enriched[0]
        assert len(enriched[0]["remediation"]) == 2
        ports = [r["port"] for r in enriched[0]["remediation"]]
        assert 22 in ports
        assert 80 in ports

    def test_enriches_hydra_findings(self, engine):
        findings = [
            {
                "tool": "hydra",
                "target": "10.10.10.1",
                "parsed_output": None,
            }
        ]
        enriched = engine.enrich_findings(findings)
        assert "remediation" in enriched[0]
        assert "password" in enriched[0]["remediation"][0]["remediation"].lower()

    def test_returns_same_list_reference(self, engine):
        findings = [{"tool": "gobuster", "target": "x"}]
        result = engine.enrich_findings(findings)
        assert result is findings

    def test_nmap_skips_closed_ports(self, engine):
        findings = [
            {
                "tool": "nmap",
                "target": "10.10.10.1",
                "parsed_output": {
                    "hosts": [
                        {
                            "address": "10.10.10.1",
                            "ports": [
                                {"port": 22, "state": "open"},
                                {"port": 443, "state": "closed"},
                            ],
                        }
                    ]
                },
            }
        ]
        enriched = engine.enrich_findings(findings)
        assert len(enriched[0]["remediation"]) == 1
