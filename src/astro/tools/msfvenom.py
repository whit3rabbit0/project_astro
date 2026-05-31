"""Msfvenom payload generation tool."""
import re
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args, validate_path
from astro.tools.base import BaseTool


_VALID_FORMATS = frozenset({
    "raw", "elf", "exe", "php", "py", "ps1", "asp", "aspx", "jsp", "war", "bash", "sh", "python", "c", "perl",
})
_ENCODER_RE = re.compile(r'^[a-zA-Z0-9/._-]+$')


class MsfvenomTool(BaseTool):
    name = "msfvenom"
    description = "Metasploit payload generator for shellcode and executable payloads"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        payload = params.get("payload", "")
        if not payload:
            raise ValueError("payload is required")
        if "/" not in payload:
            raise ValueError("payload must contain '/' (e.g. windows/meterpreter/reverse_tcp)")
        # Allow '/' but reject all other shell metacharacters
        stripped = payload.replace("/", "")
        if SHELL_METACHARACTERS.search(stripped):
            raise ValueError("Invalid payload parameter")

        lhost = params.get("lhost", "")
        if not lhost:
            raise ValueError("lhost is required")
        if not all(c.isalnum() or c in ".-" for c in lhost):
            raise ValueError("Invalid lhost parameter")

        lport = str(params.get("lport", ""))
        if not lport.isdigit() or not (1 <= int(lport) <= 65535):
            raise ValueError("lport must be a number between 1 and 65535")

        fmt = params.get("format", "raw")
        if fmt not in _VALID_FORMATS:
            raise ValueError(f"format must be one of: {', '.join(sorted(_VALID_FORMATS))}")

        encoder = params.get("encoder", "")
        if encoder and not _ENCODER_RE.match(encoder):
            raise ValueError("Invalid encoder parameter")

        iterations = str(params.get("iterations", "1"))
        if not iterations.isdigit():
            raise ValueError("iterations must be a positive integer")

        output_file = params.get("output_file", "")
        if output_file and not validate_path(output_file):
            raise ValueError("Invalid output_file: must be an absolute path with safe characters")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
            "format": fmt,
            "encoder": encoder,
            "iterations": iterations,
            "output_file": output_file,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = [
            "msfvenom",
            "-p", params["payload"],
            f"LHOST={params['lhost']}",
            f"LPORT={params['lport']}",
            "-f", params["format"],
        ]
        if params["encoder"]:
            cmd += ["-e", params["encoder"], "-i", params["iterations"]]
        if params["output_file"]:
            cmd += ["-o", params["output_file"]]
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        return {
            "payload": params["payload"],
            "format": params["format"],
            "lhost": params["lhost"],
            "lport": params["lport"],
            "output_file": params["output_file"] if params["output_file"] else "stdout",
        }
