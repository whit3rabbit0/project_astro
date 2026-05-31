"""Nikto web server scanner tool."""
import re
from typing import Any

from astro.core.validators import validate_additional_args
from astro.tools.base import BaseTool


class NiktoTool(BaseTool):
    name = "nikto"
    description = "Web server vulnerability scanner"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params.get("target", "")
        if not target:
            raise ValueError("Target parameter is required")
        if not re.fullmatch(r'[a-zA-Z0-9.\-_:/]+', target):
            raise ValueError("Invalid target parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"target": target, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["nikto", "-h", params["target"]]
        cmd.extend(params["tokens"])
        return cmd
