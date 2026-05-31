"""WPScan WordPress vulnerability scanner."""
import json
from typing import Any

from astro.core.validators import validate_additional_args, validate_url
from astro.tools.base import BaseTool


class WpscanTool(BaseTool):
    name = "wpscan"
    description = "WordPress security scanner"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        url = params.get("url", "")
        if not url:
            raise ValueError("URL parameter is required")
        if not validate_url(url):
            raise ValueError("Invalid URL parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"url": url, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["wpscan", "--url", params["url"], "--format", "json"]
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        stdout = raw.get("stdout", "")
        if not stdout:
            return None
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return None
