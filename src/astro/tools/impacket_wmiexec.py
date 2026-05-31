"""ImpacketWmiexecTool — Remote command execution via WMI — stealthier than PsExec."""
import re
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_HASHES_RE = re.compile(r'^[0-9a-fA-F:]+$')


def _build_auth(domain: str, username: str, target: str, password: str = "", hashes: str = "") -> list[str]:
    if hashes:
        return [f"{domain}/{username}@{target}", "-hashes", hashes]
    return [f"{domain}/{username}:{password}@{target}"]


class ImpacketWmiexecTool(BaseTool):
    name = "impacket-wmiexec"
    description = "Remote command execution via WMI — stealthier than PsExec"

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

        command = params.get("command", "")
        if not command:
            raise ValueError("Command parameter is required")
        if SHELL_METACHARACTERS.search(command):
            raise ValueError("Invalid command parameter")

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
            "command": command,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        auth_parts = _build_auth(
            params["domain"], params["username"], params["target"],
            params["password"], params["hashes"]
        )
        cmd = ["impacket-wmiexec", *auth_parts, params["command"]]
        cmd.extend(params["tokens"])
        return cmd
