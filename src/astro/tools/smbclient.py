"""SmbclientTool — SMB share interaction."""
import re
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_FILE_LISTING_RE = re.compile(
    r'^\s+(\S.+?)\s+[AHSDR]+\s+\d+\s+\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d{4}',
    re.MULTILINE,
)


class SmbclientTool(BaseTool):
    name = "smbclient"
    description = "SMB share access and file interaction tool"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params.get("target", "")
        if not target:
            raise ValueError("Target parameter is required")
        if not target.startswith("//"):
            raise ValueError("Target must start with '//' (e.g., '//10.10.10.10/share')")
        if SHELL_METACHARACTERS.search(target):
            raise ValueError("Target contains disallowed shell metacharacters")

        username = params.get("username", "")
        if username and SHELL_METACHARACTERS.search(username):
            raise ValueError("Invalid username parameter")

        password = params.get("password", "")
        if password and SHELL_METACHARACTERS.search(password):
            raise ValueError("Invalid password parameter")

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
            "command": command,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["smbclient", params["target"]]
        if params["username"]:
            credential = params["username"]
            if params["password"]:
                credential = f"{params['username']}%{params['password']}"
            cmd += ["-U", credential]
        if params["command"]:
            cmd += ["-c", params["command"]]
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        stdout = raw.get("stdout", "")
        files = _FILE_LISTING_RE.findall(stdout)
        return {"files": [f.strip() for f in files]}
