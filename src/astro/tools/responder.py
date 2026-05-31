"""ResponderTool — LLMNR/NBT-NS/MDNS poisoner for credential capture.

Responder runs continuously; the 300 s executor timeout will terminate it and
capture whatever credentials were gathered before the cutoff.
"""
import re
from typing import Any

from astro.core.validators import validate_additional_args
from astro.tools.base import BaseTool

_INTERFACE_RE = re.compile(r'^[a-zA-Z0-9]+$')


class ResponderTool(BaseTool):
    name = "responder"
    description = "LLMNR/NBT-NS/MDNS poisoner for network credential capture"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        interface = params.get("interface", "")
        if not interface:
            raise ValueError("Interface parameter is required")
        if not _INTERFACE_RE.match(interface):
            raise ValueError(
                "Interface must contain only alphanumeric characters (e.g., 'eth0', 'tun0')"
            )

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"interface": interface, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["responder", "-I", params["interface"]]
        cmd.extend(params["tokens"])
        return cmd
