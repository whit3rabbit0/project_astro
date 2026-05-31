"""Nmap tool with XML output parsing via python-libnmap."""
import os
import tempfile
from typing import Any

from astro.core.validators import NMAP_SCAN_FLAGS, validate_additional_args
from astro.tools.base import BaseTool, ToolResult
from astro.parsers.nmap_parser import NmapStructuredParser

_parser = NmapStructuredParser()


class NmapTool(BaseTool):
    name = "nmap"
    description = "Network exploration and port scanning tool"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params.get("target", "")
        if not target:
            raise ValueError("Target parameter is required")
        if not all(c.isalnum() or c in ".-_" for c in target):
            raise ValueError("Invalid target parameter")

        scan_type = params.get("scan_type", "-sV")
        if scan_type not in NMAP_SCAN_FLAGS:
            raise ValueError(f"Invalid scan_type. Must be one of: {', '.join(sorted(NMAP_SCAN_FLAGS))}")

        ports = params.get("ports", "")
        if ports and not all(c.isdigit() or c in ",-" for c in ports):
            raise ValueError("Invalid ports parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"target": target, "scan_type": scan_type, "ports": ports, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["nmap", params["scan_type"]]
        if params["ports"]:
            cmd += ["-p", params["ports"]]
        cmd.extend(params["tokens"])
        cmd.append(params["target"])
        return cmd

    async def execute(self, executor: Any, params: dict[str, Any]) -> ToolResult:
        """Override to handle XML temp file lifecycle."""
        validated = self.validate(params)
        cmd = self.build_command(validated)

        fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="astro_nmap_")
        os.close(fd)
        cmd_with_xml = cmd + ["-oX", xml_path]

        try:
            raw = await executor.execute(cmd_with_xml)
            parsed = _parser.parse_from_file(xml_path)
        finally:
            try:
                os.remove(xml_path)
            except OSError:
                pass

        target = validated["target"]
        return ToolResult(
            tool=self.name,
            target=target,
            success=raw["success"],
            raw=raw,
            parsed=parsed,
        )
