"""Amass DNS enumeration tool."""
import re
from typing import Any

from astro.core.validators import validate_additional_args
from astro.tools.base import BaseTool

_DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9.\-]+$')
_ALLOWED_MODES = {"enum", "intel"}


class AmassTool(BaseTool):
    name = "amass"
    description = "In-depth DNS enumeration and attack surface mapping tool"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        if not domain:
            raise ValueError("Domain parameter is required")
        if not _DOMAIN_PATTERN.match(domain):
            raise ValueError("Invalid domain parameter: must match [a-zA-Z0-9.-]+")

        mode = params.get("mode", "enum")
        if mode not in _ALLOWED_MODES:
            raise ValueError(f"Invalid mode: {mode!r}. Must be one of: {', '.join(sorted(_ALLOWED_MODES))}")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"domain": domain, "target": domain, "mode": mode, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["amass", params["mode"], "-d", params["domain"]]
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        stdout: str = raw.get("stdout", "") or ""
        domain = params.get("domain", "")
        subdomains = [
            line.strip()
            for line in stdout.splitlines()
            if line.strip() and domain and domain in line
        ]
        return {"subdomains": subdomains, "count": len(subdomains)}
