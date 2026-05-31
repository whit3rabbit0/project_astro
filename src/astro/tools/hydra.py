"""Hydra password brute-force tool."""
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args, validate_path
from astro.tools.base import BaseTool


class HydraTool(BaseTool):
    name = "hydra"
    description = "Network login cracker supporting multiple protocols"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params.get("target", "")
        service = params.get("service", "")
        if not target or not service:
            raise ValueError("Target and service parameters are required")

        if not all(c.isalnum() or c in ".-_:" for c in target):
            raise ValueError("Invalid target parameter")
        if not all(c.isalnum() or c in "._-" for c in service):
            raise ValueError("Invalid service parameter")

        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")

        if not (username or username_file) or not (password or password_file):
            raise ValueError("Username/username_file and password/password_file are required")

        if username and SHELL_METACHARACTERS.search(username):
            raise ValueError("Invalid username parameter")
        if username_file and not validate_path(username_file):
            raise ValueError("Invalid username_file parameter")
        if password and SHELL_METACHARACTERS.search(password):
            raise ValueError("Invalid password parameter")
        if password_file and not validate_path(password_file):
            raise ValueError("Invalid password_file parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["hydra", "-t", "4"]

        if params["username"]:
            cmd += ["-l", params["username"]]
        elif params["username_file"]:
            cmd += ["-L", params["username_file"]]

        if params["password"]:
            cmd += ["-p", params["password"]]
        elif params["password_file"]:
            cmd += ["-P", params["password_file"]]

        cmd.extend(params["tokens"])
        cmd += [params["target"], params["service"]]
        return cmd
