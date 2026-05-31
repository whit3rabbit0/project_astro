import pytest

from astro.intel.attack_graph import AttackGraphBuilder


@pytest.fixture
def builder():
    return AttackGraphBuilder()


@pytest.fixture
def populated_builder(builder):
    builder.add_host("10.10.10.1", os="Linux", status="up")
    builder.add_service("10.10.10.1", 22, "ssh", "OpenSSH 8.9")
    builder.add_service("10.10.10.1", 80, "http", "Apache 2.4.49")
    builder.add_vulnerability("10.10.10.1:80", "CVE-2021-41773", 9.8, "Path traversal")
    builder.add_vulnerability("10.10.10.1:22", "CVE-2023-99999", 5.0, "Low sev issue")
    return builder


class TestAddHost:
    def test_adds_host_node(self, builder):
        builder.add_host("10.10.10.1", os="Linux", status="up")
        nodes = dict(builder.graph.nodes(data=True))
        assert "10.10.10.1" in nodes
        assert nodes["10.10.10.1"]["type"] == "host"
        assert nodes["10.10.10.1"]["os"] == "Linux"
        assert nodes["10.10.10.1"]["status"] == "up"

    def test_defaults(self, builder):
        builder.add_host("10.0.0.1")
        nodes = dict(builder.graph.nodes(data=True))
        assert nodes["10.0.0.1"]["os"] == ""
        assert nodes["10.0.0.1"]["status"] == "up"


class TestAddService:
    def test_adds_service_node_and_edge(self, builder):
        builder.add_host("10.10.10.1")
        builder.add_service("10.10.10.1", 80, "http", "Apache 2.4")
        nodes = dict(builder.graph.nodes(data=True))
        assert "10.10.10.1:80" in nodes
        assert nodes["10.10.10.1:80"]["type"] == "service"
        assert nodes["10.10.10.1:80"]["service"] == "http"
        assert builder.graph.has_edge("10.10.10.1", "10.10.10.1:80")


class TestAddVulnerability:
    def test_adds_vulnerability_node_and_edge(self, builder):
        builder.add_host("10.10.10.1")
        builder.add_service("10.10.10.1", 80, "http")
        builder.add_vulnerability("10.10.10.1:80", "CVE-2021-1234", 9.8, "Critical RCE")
        nodes = dict(builder.graph.nodes(data=True))
        assert "CVE-2021-1234" in nodes
        assert nodes["CVE-2021-1234"]["type"] == "vulnerability"
        assert nodes["CVE-2021-1234"]["cvss_score"] == 9.8
        assert builder.graph.has_edge("10.10.10.1:80", "CVE-2021-1234")


class TestBuildFromNmap:
    def test_populates_from_parsed_nmap(self, builder):
        parsed = {
            "hosts": [
                {
                    "address": "10.10.10.1",
                    "os": "Linux",
                    "status": "up",
                    "ports": [
                        {"port": 22, "service": "ssh", "version": "OpenSSH 8.9"},
                        {"port": 80, "service": "http", "version": "Apache 2.4.49"},
                    ],
                }
            ]
        }
        builder.build_from_nmap(parsed)
        nodes = dict(builder.graph.nodes(data=True))
        assert "10.10.10.1" in nodes
        assert "10.10.10.1:22" in nodes
        assert "10.10.10.1:80" in nodes

    def test_skips_hosts_without_address(self, builder):
        parsed = {"hosts": [{"address": "", "ports": []}]}
        builder.build_from_nmap(parsed)
        assert len(builder.graph.nodes) == 0

    def test_handles_empty_hosts(self, builder):
        builder.build_from_nmap({"hosts": []})
        assert len(builder.graph.nodes) == 0


class TestBuildFromCves:
    def test_adds_cve_nodes_for_existing_services(self, builder):
        builder.add_host("10.10.10.1")
        builder.add_service("10.10.10.1", 80, "http")
        cves = [
            {
                "host": "10.10.10.1",
                "port": 80,
                "id": "CVE-2021-41773",
                "cvss_score": 9.8,
                "description": "Path traversal",
            }
        ]
        builder.build_from_cves(cves)
        nodes = dict(builder.graph.nodes(data=True))
        assert "CVE-2021-41773" in nodes

    def test_skips_cves_for_missing_services(self, builder):
        cves = [
            {
                "host": "10.10.10.1",
                "port": 80,
                "id": "CVE-2021-41773",
                "cvss_score": 9.8,
                "description": "Path traversal",
            }
        ]
        builder.build_from_cves(cves)
        assert "CVE-2021-41773" not in dict(builder.graph.nodes(data=True))


class TestGetAttackPaths:
    def test_finds_path_to_high_severity_vuln(self, populated_builder):
        paths = populated_builder.get_attack_paths(min_cvss=7.0)
        assert len(paths) >= 1
        found = any("CVE-2021-41773" in path for path in paths)
        assert found

    def test_excludes_low_severity_vulns(self, populated_builder):
        paths = populated_builder.get_attack_paths(min_cvss=7.0)
        for path in paths:
            assert "CVE-2023-99999" not in path

    def test_empty_graph_returns_no_paths(self, builder):
        paths = builder.get_attack_paths()
        assert paths == []

    def test_low_threshold_includes_more_vulns(self, populated_builder):
        paths = populated_builder.get_attack_paths(min_cvss=4.0)
        all_vulns = set()
        for path in paths:
            for node in path:
                if node.startswith("CVE-"):
                    all_vulns.add(node)
        assert "CVE-2021-41773" in all_vulns
        assert "CVE-2023-99999" in all_vulns


class TestToJson:
    def test_serializes_graph(self, populated_builder):
        data = populated_builder.to_json()
        assert "nodes" in data
        assert "edges" in data
        assert "stats" in data

    def test_stats_count_node_types(self, populated_builder):
        data = populated_builder.to_json()
        assert data["stats"]["hosts"] == 1
        assert data["stats"]["services"] == 2
        assert data["stats"]["vulnerabilities"] == 2

    def test_empty_graph_serializes(self, builder):
        data = builder.to_json()
        assert data["nodes"] == []
        assert data["edges"] == []
        assert data["stats"]["hosts"] == 0
