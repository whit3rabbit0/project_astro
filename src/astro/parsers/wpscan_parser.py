"""WPScan JSON output parser."""
import json
from typing import Any

from astro.parsers.base import BaseParser


class WpscanStructuredParser(BaseParser):
    def parse(self, raw_output: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        stdout = raw_output.get("stdout", "")
        if not stdout:
            return None
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return None

        return {
            "version": data.get("version"),
            "plugins": data.get("plugins", {}),
            "themes": data.get("main_theme", {}),
            "users": data.get("users", {}),
            "vulnerabilities": _collect_vulnerabilities(data),
        }


def _collect_vulnerabilities(data: dict[str, Any]) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []

    wp_version = data.get("version") or {}
    for vuln in wp_version.get("vulnerabilities", []):
        vulns.append({"source": "wordpress_core", **vuln})

    for name, plugin in (data.get("plugins") or {}).items():
        for vuln in plugin.get("vulnerabilities", []):
            vulns.append({"source": f"plugin:{name}", **vuln})

    main_theme = data.get("main_theme") or {}
    for vuln in main_theme.get("vulnerabilities", []):
        vulns.append({"source": f"theme:{main_theme.get('slug', 'unknown')}", **vuln})

    return vulns
