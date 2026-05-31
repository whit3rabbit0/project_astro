"""HashcatTool — GPU-accelerated password cracking."""
import re
from typing import Any

from astro.core.validators import validate_additional_args, validate_path
from astro.tools.base import BaseTool

_ALLOWED_ATTACK_MODES = {"0", "1", "3", "6", "7"}
_CRACKED_LINE_RE = re.compile(r'^[^:]+:.+$', re.MULTILINE)


class HashcatTool(BaseTool):
    name = "hashcat"
    description = "GPU-accelerated password hash cracker"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        hash_file = params.get("hash_file", "")
        if not hash_file:
            raise ValueError("Hash file parameter is required")
        if not validate_path(hash_file):
            raise ValueError("Invalid hash_file parameter")

        wordlist = params.get("wordlist", "")
        if wordlist and not validate_path(wordlist):
            raise ValueError("Invalid wordlist parameter")

        hash_type = params.get("hash_type", "")
        if hash_type and not hash_type.isdigit():
            raise ValueError("hash_type must be digits only")

        attack_mode = params.get("attack_mode", "0")
        if attack_mode not in _ALLOWED_ATTACK_MODES:
            raise ValueError(
                f"Invalid attack_mode. Must be one of: {', '.join(sorted(_ALLOWED_ATTACK_MODES))}"
            )

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "hash_type": hash_type,
            "attack_mode": attack_mode,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = ["hashcat", "-a", params["attack_mode"]]
        if params["hash_type"]:
            cmd += ["-m", params["hash_type"]]
        cmd.append(params["hash_file"])
        if params["wordlist"]:
            cmd.append(params["wordlist"])
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        stdout = raw.get("stdout", "")
        cracked = _CRACKED_LINE_RE.findall(stdout)
        return {"cracked": cracked, "count": len(cracked)}
