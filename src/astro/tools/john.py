"""John the Ripper password cracking tool."""
from typing import Any

from astro.core.validators import validate_additional_args, validate_path
from astro.tools.base import BaseTool


class JohnTool(BaseTool):
    name = "john"
    description = "Password cracker supporting many hash formats"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        hash_file = params.get("hash_file", "")
        if not hash_file:
            raise ValueError("Hash file parameter is required")
        if not validate_path(hash_file):
            raise ValueError("Invalid hash_file parameter")

        wordlist = params.get("wordlist", "")
        if wordlist and not validate_path(wordlist):
            raise ValueError("Invalid wordlist parameter")

        format_type = params.get("format", "")
        if format_type and not all(c.isalnum() or c in "-_" for c in format_type):
            raise ValueError("Invalid format parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format_type": format_type,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["john"]
        if params["format_type"]:
            cmd.append(f"--format={params['format_type']}")
        if params["wordlist"]:
            cmd.append(f"--wordlist={params['wordlist']}")
        cmd.extend(params["tokens"])
        cmd.append(params["hash_file"])
        return cmd
