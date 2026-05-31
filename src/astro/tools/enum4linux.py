"""Enum4linux Windows/Samba enumeration tool."""
from typing import Any

from astro.core.validators import validate_additional_args
from astro.tools.base import BaseTool


class Enum4linuxTool(BaseTool):
    name = "enum4linux"
    description = "Enumerate information from Windows and Samba hosts"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params.get("target", "")
        if not target:
            raise ValueError("Target parameter is required")
        if not all(c.isalnum() or c in ".-_:" for c in target):
            raise ValueError("Invalid target parameter")

        additional_args = params.get("additional_args", "-a")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"target": target, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["enum4linux"]
        cmd.extend(params["tokens"])
        cmd.append(params["target"])
        return cmd
