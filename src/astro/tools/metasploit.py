"""Metasploit Framework tool — uses resource scripts via msfconsole."""
import os
import re
import tempfile
from typing import Any

from astro.core.validators import validate_no_control_chars
from astro.tools.base import BaseTool, ToolResult

_MODULE_PATH_RE = re.compile(r"^[a-z0-9/_]+$")
_OPTION_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


class MetasploitTool(BaseTool):
    name = "metasploit"
    description = "Penetration testing framework — executes MSF modules via resource script"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        module = params.get("module", "")
        if not module:
            raise ValueError("Module parameter is required")
        if not _MODULE_PATH_RE.match(module):
            raise ValueError(
                "Invalid module path: only lowercase alphanumeric, '/' and '_' allowed"
            )

        options: dict[str, Any] = params.get("options", {})
        for key, value in options.items():
            key_str = str(key)
            value_str = str(value)

            if not _OPTION_KEY_RE.match(key_str):
                raise ValueError(
                    f"Invalid option key: {key_str!r} — must match ^[A-Z][A-Z0-9_]*$"
                )

            if "\n" in value_str or "\r" in value_str or "#" in value_str:
                raise ValueError(
                    f"Invalid value for option {key_str!r}: "
                    "must not contain newline, carriage return, or '#'"
                )

            if not validate_no_control_chars(value_str):
                raise ValueError(f"Invalid value for option {key_str!r}")

        return {"module": module, "options": options}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        # Resource file path is injected by execute(); placeholder here.
        return ["msfconsole", "-q", "-r", params.get("_resource_file", "")]

    async def execute(self, executor: Any, params: dict[str, Any]) -> ToolResult:
        """Override to manage resource script temp file lifecycle."""
        validated = self.validate(params)

        resource_content = f"use {validated['module']}\n"
        for key, value in validated["options"].items():
            resource_content += f"set {key} \"{value}\"\n"
        resource_content += "exploit\n"

        fd, resource_file = tempfile.mkstemp(suffix=".rc", prefix="astro_msf_")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(resource_content)
            cmd = ["msfconsole", "-q", "-r", resource_file]
            raw = await executor.execute(cmd)
        finally:
            try:
                os.remove(resource_file)
            except OSError:
                pass

        return ToolResult(
            tool=self.name,
            target=validated["module"],
            success=raw["success"],
            raw=raw,
            parsed=None,
        )
