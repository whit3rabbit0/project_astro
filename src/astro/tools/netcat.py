"""Netcat (ncat) tool for listeners and connections."""
from typing import Any

from astro.core.validators import validate_additional_args
from astro.tools.base import BaseTool


_VALID_MODES = frozenset({"listen", "connect"})


class NetcatTool(BaseTool):
    name = "netcat"
    description = "Netcat listener and connect tool using ncat"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        mode = params.get("mode", "")
        if mode not in _VALID_MODES:
            raise ValueError(f"mode must be one of: {', '.join(sorted(_VALID_MODES))}")

        port = str(params.get("port", ""))
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            raise ValueError("port must be a number between 1 and 65535")

        host = params.get("host", "")
        if mode == "connect":
            if not host:
                raise ValueError("host is required for connect mode")
            if not all(c.isalnum() or c in ".-_" for c in host):
                raise ValueError("Invalid host parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"mode": mode, "port": port, "host": host, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        if params["mode"] == "listen":
            return ["ncat", "-lvnp", params["port"], *params["tokens"]]
        return ["ncat", params["host"], params["port"], *params["tokens"]]

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        return {
            "mode": params["mode"],
            "port": params["port"],
            "host": params.get("host", ""),
        }
