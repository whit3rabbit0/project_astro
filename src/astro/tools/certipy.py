"""CertipyTool — ADCS certificate enumeration and exploitation."""
import re
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_HASHES_RE = re.compile(r'^[0-9a-fA-F:]+$')

_VALID_ACTIONS = {"find", "req", "auth", "shadow", "forge"}


class CertipyTool(BaseTool):
    name = "certipy"
    description = "ADCS certificate enumeration and exploitation"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params.get("target", "")
        if not target:
            raise ValueError("Target parameter is required")
        if not all(c.isalnum() or c in ".-_:" for c in target):
            raise ValueError("Invalid target parameter")

        domain = params.get("domain", "")
        if not domain:
            raise ValueError("Domain parameter is required")
        if not all(c.isalnum() or c in ".-" for c in domain):
            raise ValueError("Invalid domain parameter")

        username = params.get("username", "")
        if not username:
            raise ValueError("Username parameter is required")
        if SHELL_METACHARACTERS.search(username):
            raise ValueError("Invalid username parameter")

        password = params.get("password", "")
        if password and SHELL_METACHARACTERS.search(password):
            raise ValueError("Invalid password parameter")

        hashes = params.get("hashes", "")
        if hashes and not _HASHES_RE.match(hashes):
            raise ValueError("Invalid hashes parameter: must be hex and ':' only")

        action = params.get("action", "")
        if not action:
            raise ValueError("Action parameter is required")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"Invalid action: must be one of {sorted(_VALID_ACTIONS)}")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {
            "target": target,
            "domain": domain,
            "username": username,
            "password": password,
            "hashes": hashes,
            "action": action,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = [
            "certipy", params["action"],
            "-u", f"{params['username']}@{params['domain']}",
            "-dc-ip", params["target"],
        ]
        if params["action"] == "find":
            cmd.append("-vulnerable")
        if params["hashes"]:
            cmd.extend(["-hashes", params["hashes"]])
        else:
            cmd.extend(["-p", params["password"]])
        cmd.extend(params["tokens"])
        return cmd
