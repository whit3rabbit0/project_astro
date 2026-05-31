"""TheHarvester email and subdomain harvesting tool."""
import re
from typing import Any

from astro.core.validators import validate_additional_args
from astro.tools.base import BaseTool

_DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9.\-]+$')
_ALLOWED_SOURCES = {"all", "google", "bing", "linkedin", "twitter", "shodan", "censys"}


class TheHarvesterTool(BaseTool):
    name = "theharvester"
    description = "Email, subdomain, and open-source intelligence harvesting tool"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        if not domain:
            raise ValueError("Domain parameter is required")
        if not _DOMAIN_PATTERN.match(domain):
            raise ValueError("Invalid domain parameter: must match [a-zA-Z0-9.-]+")

        source = params.get("source", "all")
        if source not in _ALLOWED_SOURCES:
            raise ValueError(
                f"Invalid source: {source!r}. Must be one of: {', '.join(sorted(_ALLOWED_SOURCES))}"
            )

        limit = params.get("limit", "500")
        if not str(limit).isdigit():
            raise ValueError("Invalid limit parameter: must be digits only")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {
            "domain": domain,
            "target": domain,
            "source": source,
            "limit": str(limit),
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = [
            "theHarvester",
            "-d", params["domain"],
            "-b", params["source"],
            "-l", params["limit"],
        ]
        cmd.extend(params["tokens"])
        return cmd
