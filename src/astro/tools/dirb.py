"""Dirb web content scanner tool."""
from typing import Any

from astro.core.validators import validate_additional_args, validate_path, validate_url
from astro.tools.base import BaseTool


class DirbTool(BaseTool):
    name = "dirb"
    description = "Web content scanner using wordlists"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        url = params.get("url", "")
        if not url:
            raise ValueError("URL parameter is required")
        if not validate_url(url):
            raise ValueError("Invalid URL parameter")

        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        if not validate_path(wordlist):
            raise ValueError("Invalid wordlist parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"url": url, "wordlist": wordlist, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["dirb", params["url"], params["wordlist"]]
        cmd.extend(params["tokens"])
        return cmd
