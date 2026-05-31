"""WhatWeb web technology fingerprinting tool."""
import json
import re
from typing import Any

from astro.core.validators import validate_additional_args, validate_url
from astro.tools.base import BaseTool

_HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9.\-]+$')


class WhatwebTool(BaseTool):
    name = "whatweb"
    description = "Web technology fingerprinting tool"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params.get("target", "")
        if not target:
            raise ValueError("Target parameter is required")
        if not validate_url(target) and not _HOSTNAME_PATTERN.match(target):
            raise ValueError(
                "Invalid target: must be a URL (http:// or https://) or a plain hostname"
            )

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"target": target, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["whatweb", "--log-json=-", params["target"]]
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        stdout: str = raw.get("stdout", "") or ""
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            return None

        technologies: list[dict[str, str]] = []
        server = ""

        if not isinstance(data, list):
            data = [data]

        for entry in data:
            plugins: dict[str, Any] = entry.get("plugins") or {}
            for name, info in plugins.items():
                if not isinstance(info, dict):
                    continue
                version_list = info.get("version") or []
                version = version_list[0] if version_list else ""
                string_list = info.get("string") or []
                category = string_list[0] if string_list else ""
                technologies.append({"name": name, "version": version, "category": category})
                if name.lower() == "server" and not server:
                    server = version or category

        return {"technologies": technologies, "server": server}
