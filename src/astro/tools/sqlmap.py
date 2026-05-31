"""SQLMap SQL injection testing tool.

V2 change: --batch flag is added by default to avoid interactive prompts.
This is an intentional deviation from V1 behaviour.
"""
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool


class SqlmapTool(BaseTool):
    name = "sqlmap"
    description = "Automatic SQL injection and database takeover tool"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        url = params.get("url", "")
        if not url:
            raise ValueError("URL parameter is required")
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError("Invalid URL parameter")

        data = params.get("data", "")
        if data and SHELL_METACHARACTERS.search(data):
            raise ValueError("Invalid data parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"url": url, "data": data, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["sqlmap", "-u", params["url"]]
        if params["data"]:
            cmd += ["--data", params["data"]]
        cmd.append("--batch")
        cmd.extend(params["tokens"])
        return cmd
