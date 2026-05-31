"""Chisel tunneling tool for pivoting and port forwarding."""
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool


_VALID_MODES = frozenset({"server", "client"})


class ChiselTool(BaseTool):
    name = "chisel"
    description = "Fast TCP/UDP tunnel for pivoting and port forwarding"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        mode = params.get("mode", "")
        if mode not in _VALID_MODES:
            raise ValueError(f"mode must be one of: {', '.join(sorted(_VALID_MODES))}")

        port = str(params.get("port", ""))
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            raise ValueError("port must be a number between 1 and 65535")

        host = params.get("host", "")
        remote = params.get("remote", "")

        if mode == "client":
            if not host:
                raise ValueError("host is required for client mode")
            if not all(c.isalnum() or c in ".-_" for c in host):
                raise ValueError("Invalid host parameter")
            if not remote:
                raise ValueError("remote is required for client mode")
            if SHELL_METACHARACTERS.search(remote):
                raise ValueError("Invalid remote parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"mode": mode, "port": port, "host": host, "remote": remote, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        if params["mode"] == "server":
            return ["chisel", "server", "--port", params["port"], "--reverse", *params["tokens"]]
        return ["chisel", "client", f"{params['host']}:{params['port']}", params["remote"], *params["tokens"]]

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        return {
            "mode": params["mode"],
            "port": params["port"],
            "host": params.get("host", ""),
            "remote": params.get("remote", ""),
        }
