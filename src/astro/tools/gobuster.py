"""Gobuster directory/DNS/vhost brute-force tool."""
from typing import Any

from astro.core.validators import validate_additional_args, validate_path, validate_url
from astro.tools.base import BaseTool

_ALLOWED_MODES = {"dir", "dns", "fuzz", "vhost"}


class GobusterTool(BaseTool):
    name = "gobuster"
    description = "Directory and DNS brute-force tool"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        url = params.get("url", "")
        if not url:
            raise ValueError("URL parameter is required")
        if not validate_url(url):
            raise ValueError("Invalid URL parameter")

        mode = params.get("mode", "dir")
        if mode not in _ALLOWED_MODES:
            raise ValueError(f"Invalid mode: {mode}. Must be one of: {', '.join(sorted(_ALLOWED_MODES))}")

        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        if not validate_path(wordlist):
            raise ValueError("Invalid wordlist parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"url": url, "mode": mode, "wordlist": wordlist, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["gobuster", params["mode"], "-u", params["url"], "-w", params["wordlist"]]
        cmd.extend(params["tokens"])
        return cmd
