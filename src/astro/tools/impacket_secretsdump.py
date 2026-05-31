"""ImpacketSecretsdumpTool — Dump credentials via DCSync, SAM, LSA, or NTDS.dit."""
import re
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_HASHES_RE = re.compile(r'^[0-9a-fA-F:]+$')
_CRED_LINE_RE = re.compile(
    r'^([^:\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})', re.MULTILINE
)


def _build_auth(domain: str, username: str, target: str, password: str = "", hashes: str = "") -> list[str]:
    if hashes:
        return [f"{domain}/{username}@{target}", "-hashes", hashes]
    return [f"{domain}/{username}:{password}@{target}"]


class ImpacketSecretsdumpTool(BaseTool):
    name = "impacket-secretsdump"
    description = "Dump credentials via DCSync, SAM, LSA, or NTDS.dit"

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
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        auth_parts = _build_auth(
            params["domain"], params["username"], params["target"],
            params["password"], params["hashes"]
        )
        cmd = ["impacket-secretsdump", *auth_parts]
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        stdout = raw.get("stdout", "")
        credentials = [
            {"user": m.group(1), "rid": m.group(2), "lm_hash": m.group(3), "nt_hash": m.group(4)}
            for m in _CRED_LINE_RE.finditer(stdout)
        ]
        return {"credentials": credentials, "count": len(credentials)}
