"""EvilWinrmTool — WinRM shell for Windows lateral movement and post-exploitation."""
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


class EvilWinrmTool(BaseTool):
    name = "evil-winrm"
    description = "WinRM shell for Windows lateral movement and post-exploitation"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params.get("target", "")
        if not target:
            raise ValueError("Target parameter is required")
        if not all(c.isalnum() or c in ".-_:" for c in target):
            raise ValueError("Invalid target parameter")

        username = params.get("username", "")
        if not username:
            raise ValueError("Username parameter is required")
        if SHELL_METACHARACTERS.search(username):
            raise ValueError("Invalid username parameter")

        password = params.get("password", "")
        if password and SHELL_METACHARACTERS.search(password):
            raise ValueError("Invalid password parameter")

        hash_ = params.get("hash", "")
        if hash_ and not all(c in _HEX_CHARS or c == ":" for c in hash_):
            raise ValueError("Invalid hash parameter: expected hex string or NTLM hash (LM:NT)")

        if not password and not hash_:
            raise ValueError("Either password or hash must be provided")

        command = params.get("command", "")
        if command and SHELL_METACHARACTERS.search(command):
            raise ValueError("Invalid command parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {
            "target": target,
            "username": username,
            "password": password,
            "hash": hash_,
            "command": command,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["evil-winrm", "-i", params["target"], "-u", params["username"]]
        if params["password"]:
            cmd += ["-p", params["password"]]
        elif params["hash"]:
            cmd += ["-H", params["hash"]]
        if params["command"]:
            cmd += ["-e", params["command"]]
        cmd.extend(params["tokens"])
        return cmd
