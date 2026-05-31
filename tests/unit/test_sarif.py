import json

import pytest

from astro.reporting.sarif import SARIFGenerator


@pytest.fixture
def generator():
    return SARIFGenerator()


@pytest.fixture
def nmap_finding():
    return {
        "tool": "nmap",
        "target": "10.10.10.1",
        "parsed_output": {
            "hosts": [
                {
                    "address": "10.10.10.1",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "version": "OpenSSH 8.9",
                        },
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                            "version": "Apache 2.4.49",
                        },
                        {
                            "port": 443,
                            "protocol": "tcp",
                            "state": "closed",
                            "service": "https",
                            "version": "",
                        },
                    ],
                }
            ]
        },
    }


@pytest.fixture
def sample_cves():
    return [
        {
            "id": "CVE-2021-41773",
            "description": "Path traversal in Apache 2.4.49",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "cwes": ["CWE-22"],
            "host": "10.10.10.1",
        },
        {
            "id": "CVE-2023-99999",
            "description": "Low severity info disclosure",
            "cvss_score": 3.1,
            "cvss_severity": "LOW",
            "cwes": [],
            "host": "10.10.10.1",
        },
    ]


class TestSarifVersion:
    def test_version_is_2_1_0(self, generator):
        report = generator.generate([])
        assert report["version"] == "2.1.0"

    def test_schema_uri_present(self, generator):
        report = generator.generate([])
        assert "sarif-schema-2.1.0.json" in report["$schema"]


class TestSarifStructure:
    def test_has_runs_array(self, generator):
        report = generator.generate([])
        assert "runs" in report
        assert isinstance(report["runs"], list)
        assert len(report["runs"]) == 1

    def test_run_has_tool_driver(self, generator):
        report = generator.generate([])
        driver = report["runs"][0]["tool"]["driver"]
        assert driver["name"] == "project-astro"
        assert driver["version"] == "2.0.0"

    def test_custom_tool_name(self):
        gen = SARIFGenerator(tool_name="custom-tool", tool_version="1.0.0")
        report = gen.generate([])
        driver = report["runs"][0]["tool"]["driver"]
        assert driver["name"] == "custom-tool"


class TestNmapFindingsInSarif:
    def test_generates_results_for_open_ports(self, generator, nmap_finding):
        report = generator.generate([nmap_finding])
        results = report["runs"][0]["results"]
        assert len(results) == 2

    def test_skips_closed_ports(self, generator, nmap_finding):
        report = generator.generate([nmap_finding])
        results = report["runs"][0]["results"]
        rule_ids = [r["ruleId"] for r in results]
        assert "open-port-443" not in rule_ids

    def test_rule_ids_match_port_numbers(self, generator, nmap_finding):
        report = generator.generate([nmap_finding])
        results = report["runs"][0]["results"]
        rule_ids = [r["ruleId"] for r in results]
        assert "open-port-22" in rule_ids
        assert "open-port-80" in rule_ids

    def test_result_level_is_note(self, generator, nmap_finding):
        report = generator.generate([nmap_finding])
        results = report["runs"][0]["results"]
        assert all(r["level"] == "note" for r in results)


class TestCveFindingsInSarif:
    def test_generates_results_for_cves(self, generator, sample_cves):
        report = generator.generate([], cves=sample_cves)
        results = report["runs"][0]["results"]
        assert len(results) == 2

    def test_critical_cve_maps_to_error_level(self, generator, sample_cves):
        report = generator.generate([], cves=sample_cves)
        results = report["runs"][0]["results"]
        critical = next(r for r in results if r["ruleId"] == "CVE-2021-41773")
        assert critical["level"] == "error"

    def test_low_cve_maps_to_note_level(self, generator, sample_cves):
        report = generator.generate([], cves=sample_cves)
        results = report["runs"][0]["results"]
        low = next(r for r in results if r["ruleId"] == "CVE-2023-99999")
        assert low["level"] == "note"

    def test_cve_rules_have_properties(self, generator, sample_cves):
        report = generator.generate([], cves=sample_cves)
        rules = report["runs"][0]["tool"]["driver"]["rules"]
        cve_rule = next(r for r in rules if r["id"] == "CVE-2021-41773")
        assert cve_rule["properties"]["cvss_score"] == 9.8
        assert "CWE-22" in cve_rule["properties"]["cwes"]


class TestToJson:
    def test_returns_valid_json_string(self, generator, nmap_finding):
        json_str = generator.to_json([nmap_finding])
        data = json.loads(json_str)
        assert data["version"] == "2.1.0"

    def test_respects_indent(self, generator):
        json_str = generator.to_json([], indent=4)
        assert "    " in json_str
