"""CrackMapExecTool — AD/SMB lateral movement and credential testing.

Newer versions ship as `netexec` (nxc); this tool falls back to `nxc` when
`crackmapexec` is not found on PATH.
"""
import shutil
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_ALLOWED_PROTOCOLS = {"smb", "ssh", "winrm", "ldap", "mssql", "rdp", "ftp"}


def _resolve_binary() -> str:
    return shutil.which("crackmapexec") or shutil.which("nxc") or "crackmapexec"


class CrackMapExecTool(BaseTool):
    name = "crackmapexec"
    description = "Active Directory / SMB lateral movement and credential testing tool"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        protocol = params.get("protocol", "")
        if not protocol:
            raise ValueError("Protocol parameter is required")
        if protocol not in _ALLOWED_PROTOCOLS:
            raise ValueError(
                f"Invalid protocol. Must be one of: {', '.join(sorted(_ALLOWED_PROTOCOLS))}"
            )

        target = params.get("target", "")
        if not target:
            raise ValueError("Target parameter is required")
        if not all(c.isalnum() or c in ".-_:/" for c in target):
            raise ValueError("Invalid target parameter")

        username = params.get("username", "")
        if username and SHELL_METACHARACTERS.search(username):
            raise ValueError("Invalid username parameter")

        password = params.get("password", "")
        if password and SHELL_METACHARACTERS.search(password):
            raise ValueError("Invalid password parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {
            "protocol": protocol,
            "target": target,
            "username": username,
            "password": password,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        binary = _resolve_binary()
        cmd = [binary, params["protocol"], params["target"]]
        if params["username"]:
            cmd += ["-u", params["username"]]
        if params["password"]:
            cmd += ["-p", params["password"]]
        cmd.extend(params["tokens"])
        return cmd
