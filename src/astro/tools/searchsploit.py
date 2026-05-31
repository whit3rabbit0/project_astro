"""SearchsploitTool — Exploit-DB local search, pairs with CVE correlator."""
import json
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_EXPLOIT_FIELDS = ("Title", "Path", "Type", "Platform")


class SearchsploitTool(BaseTool):
    name = "searchsploit"
    description = "Search Exploit-DB local copy for exploits matching a service, CVE, or product"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        query = params.get("query", "")
        if not query:
            raise ValueError("Query parameter is required")
        if SHELL_METACHARACTERS.search(query):
            raise ValueError("Query contains disallowed shell metacharacters")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"query": query, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        return ["searchsploit", "--json", params["query"], *params["tokens"]]

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        stdout = raw.get("stdout", "")
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, TypeError):
            return {"exploits": [], "count": 0}

        results = data.get("RESULTS_EXPLOIT", [])
        exploits = [
            {
                "title": entry.get("Title", ""),
                "path": entry.get("Path", ""),
                "type": entry.get("Type", ""),
                "platform": entry.get("Platform", ""),
            }
            for entry in results
            if isinstance(entry, dict)
        ]
        return {"exploits": exploits, "count": len(exploits)}
