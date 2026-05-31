"""Ffuf fast web fuzzer tool."""
import json
from typing import Any

from astro.core.validators import validate_additional_args, validate_path, validate_url
from astro.tools.base import BaseTool

_DEFAULT_MATCH_CODES = "200,301,302,403"


class FfufTool(BaseTool):
    name = "ffuf"
    description = "Fast web fuzzer for directory and parameter discovery"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        url = params.get("url", "")
        if not url:
            raise ValueError("URL parameter is required")
        if "FUZZ" not in url:
            raise ValueError("URL must contain the FUZZ keyword")
        # validate_url checks http(s):// prefix and no shell metacharacters
        # FUZZ letters are safe, so pass the url as-is
        if not validate_url(url):
            raise ValueError("Invalid URL parameter: must start with http:// or https:// and contain no shell metacharacters")

        wordlist = params.get("wordlist", "")
        if not wordlist:
            raise ValueError("Wordlist parameter is required")
        if not validate_path(wordlist):
            raise ValueError("Invalid wordlist parameter: must be an absolute path with safe characters")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"url": url, "wordlist": wordlist, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = [
            "ffuf",
            "-u", params["url"],
            "-w", params["wordlist"],
            "-mc", _DEFAULT_MATCH_CODES,
        ]
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        stdout: str = raw.get("stdout", "") or ""
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            return None

        results: list[dict[str, Any]] = []
        for entry in data.get("results", []):
            results.append({
                "url": entry.get("url", ""),
                "status": entry.get("status", 0),
                "length": entry.get("length", 0),
                "words": entry.get("words", 0),
            })
        return {"results": results, "count": len(results)}
