import json

import pytest

from astro.parsers.generic_parser import GenericParser
from astro.parsers.sqlmap_parser import SqlmapStructuredParser
from astro.parsers.wpscan_parser import WpscanStructuredParser


class TestGenericParser:
    def test_returns_none(self):
        parser = GenericParser()
        result = parser.parse({"stdout": "some output"}, {})
        assert result is None

    def test_returns_none_with_empty_input(self):
        parser = GenericParser()
        result = parser.parse({}, {})
        assert result is None


class TestWpscanStructuredParser:
    def test_parses_valid_json_output(self):
        parser = WpscanStructuredParser()
        wpscan_data = {
            "version": {"number": "6.2", "vulnerabilities": []},
            "plugins": {
                "akismet": {
                    "slug": "akismet",
                    "vulnerabilities": [
                        {"title": "Akismet XSS", "fixed_in": "4.2.1"}
                    ],
                }
            },
            "main_theme": {
                "slug": "twentytwentythree",
                "vulnerabilities": [],
            },
            "users": {"admin": {"id": 1}},
        }
        raw = {"stdout": json.dumps(wpscan_data)}
        result = parser.parse(raw, {})
        assert result is not None
        assert result["version"] == {"number": "6.2", "vulnerabilities": []}
        assert "akismet" in result["plugins"]
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["source"] == "plugin:akismet"

    def test_returns_none_on_empty_stdout(self):
        parser = WpscanStructuredParser()
        result = parser.parse({"stdout": ""}, {})
        assert result is None

    def test_returns_none_on_invalid_json(self):
        parser = WpscanStructuredParser()
        result = parser.parse({"stdout": "not json"}, {})
        assert result is None

    def test_collects_core_vulnerabilities(self):
        parser = WpscanStructuredParser()
        wpscan_data = {
            "version": {
                "number": "5.0",
                "vulnerabilities": [
                    {"title": "WP Core RCE", "fixed_in": "5.0.1"}
                ],
            },
        }
        raw = {"stdout": json.dumps(wpscan_data)}
        result = parser.parse(raw, {})
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["source"] == "wordpress_core"

    def test_collects_theme_vulnerabilities(self):
        parser = WpscanStructuredParser()
        wpscan_data = {
            "main_theme": {
                "slug": "mytheme",
                "vulnerabilities": [
                    {"title": "Theme XSS", "fixed_in": "1.2"}
                ],
            },
        }
        raw = {"stdout": json.dumps(wpscan_data)}
        result = parser.parse(raw, {})
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["source"] == "theme:mytheme"


class TestSqlmapStructuredParser:
    def test_parses_json_output(self):
        parser = SqlmapStructuredParser()
        data = {"injections": [{"parameter": "id"}], "databases": ["testdb"]}
        raw = {"stdout": json.dumps(data)}
        result = parser.parse(raw, {})
        assert result == data

    def test_returns_none_on_empty_stdout(self):
        parser = SqlmapStructuredParser()
        result = parser.parse({"stdout": ""}, {})
        assert result is None

    def test_parses_text_injection_output(self):
        parser = SqlmapStructuredParser()
        text_output = (
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind\n"
            "---\n"
        )
        raw = {"stdout": text_output}
        result = parser.parse(raw, {})
        assert result is not None
        assert len(result["injections"]) == 1
        assert result["injections"][0]["parameter"] == "id"
        assert result["injections"][0]["type"] == "boolean-based blind"

    def test_parses_database_listing(self):
        parser = SqlmapStructuredParser()
        text_output = (
            "available databases [3]:\n"
            "[*] information_schema\n"
            "[*] mysql\n"
            "[*] webapp\n"
        )
        raw = {"stdout": text_output}
        result = parser.parse(raw, {})
        assert result is not None
        assert result["databases"] == ["information_schema", "mysql", "webapp"]

    def test_returns_none_on_no_findings(self):
        parser = SqlmapStructuredParser()
        raw = {"stdout": "nothing interesting found"}
        result = parser.parse(raw, {})
        assert result is None
