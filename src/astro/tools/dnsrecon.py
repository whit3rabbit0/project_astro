"""Dnsrecon DNS reconnaissance tool."""
import re
from typing import Any

from astro.core.validators import validate_additional_args
from astro.tools.base import BaseTool

_DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9.\-]+$')
_ALLOWED_SCAN_TYPES = {"std", "brt", "rvl", "axfr"}


class DnsreconTool(BaseTool):
    name = "dnsrecon"
    description = "DNS reconnaissance and enumeration tool"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        if not domain:
            raise ValueError("Domain parameter is required")
        if not _DOMAIN_PATTERN.match(domain):
            raise ValueError("Invalid domain parameter: must match [a-zA-Z0-9.-]+")

        scan_type = params.get("scan_type", "std")
        if scan_type not in _ALLOWED_SCAN_TYPES:
            raise ValueError(
                f"Invalid scan_type: {scan_type!r}. Must be one of: {', '.join(sorted(_ALLOWED_SCAN_TYPES))}"
            )

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"domain": domain, "target": domain, "scan_type": scan_type, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["dnsrecon", "-d", params["domain"], "-t", params["scan_type"]]
        cmd.extend(params["tokens"])
        return cmd
