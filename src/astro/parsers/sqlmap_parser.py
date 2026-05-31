"""SQLMap output parser — extracts structured injection findings from stdout."""
import json
import re
from typing import Any

from astro.parsers.base import BaseParser

_INJECTION_RE = re.compile(
    r"Parameter:\s+(.+?)\s+\((.+?)\)\s*\n.*?Type:\s+(.+?)\n.*?Title:\s+(.+?)\n",
    re.DOTALL,
)


class SqlmapStructuredParser(BaseParser):
    def parse(self, raw_output: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        stdout = raw_output.get("stdout", "")
        if not stdout:
            return None

        # Attempt JSON parse first (sqlmap --output-dir JSON mode).
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            pass

        return _parse_text_output(stdout)


def _parse_text_output(stdout: str) -> dict[str, Any] | None:
    injections = []
    for match in _INJECTION_RE.finditer(stdout):
        injections.append({
            "parameter": match.group(1).strip(),
            "place": match.group(2).strip(),
            "type": match.group(3).strip(),
            "title": match.group(4).strip(),
        })

    databases: list[str] = []
    db_section = re.search(r"available databases \[\d+\]:\n((?:\[\*\] .+\n?)+)", stdout)
    if db_section:
        databases = re.findall(r"\[\*\] (.+)", db_section.group(1))

    if not injections and not databases:
        return None

    return {"injections": injections, "databases": databases}
