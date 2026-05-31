"""Subfinder subdomain discovery tool."""
import re
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9.\-]+$')


class SubfinderTool(BaseTool):
    name = "subfinder"
    description = "Passive subdomain discovery tool"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        if not domain:
            raise ValueError("Domain parameter is required")
        if not _DOMAIN_PATTERN.match(domain):
            raise ValueError("Invalid domain parameter: must match [a-zA-Z0-9.-]+")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"domain": domain, "target": domain, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["subfinder", "-d", params["domain"], "-silent"]
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        stdout: str = raw.get("stdout", "") or ""
        subdomains = [line.strip() for line in stdout.splitlines() if line.strip()]
        return {"subdomains": subdomains, "count": len(subdomains)}
