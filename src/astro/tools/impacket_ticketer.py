"""ImpacketTicketerTool — Forge Kerberos golden or silver tickets."""
import re
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_NTHASH_RE = re.compile(r'^[a-fA-F0-9]+$')
_DOMAIN_SID_RE = re.compile(r'^S-1-5-[0-9-]+$')


class ImpacketTicketerTool(BaseTool):
    name = "impacket-ticketer"
    description = "Forge Kerberos golden or silver tickets"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        domain = params.get("domain", "")
        if not domain:
            raise ValueError("Domain parameter is required")
        if not all(c.isalnum() or c in ".-" for c in domain):
            raise ValueError("Invalid domain parameter")

        domain_sid = params.get("domain_sid", "")
        if not domain_sid:
            raise ValueError("Domain SID parameter is required")
        if not _DOMAIN_SID_RE.match(domain_sid):
            raise ValueError("Invalid domain_sid parameter: must match S-1-5-... format")

        nthash = params.get("nthash", "")
        if not nthash:
            raise ValueError("NT hash parameter is required")
        if not _NTHASH_RE.match(nthash):
            raise ValueError("Invalid nthash parameter: must be hex only")

        user = params.get("user", "")
        if not user:
            raise ValueError("User parameter is required")
        if SHELL_METACHARACTERS.search(user):
            raise ValueError("Invalid user parameter")

        spn = params.get("spn", "")
        if spn and SHELL_METACHARACTERS.search(spn):
            raise ValueError("Invalid spn parameter")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {
            "target": domain,
            "domain": domain,
            "domain_sid": domain_sid,
            "nthash": nthash,
            "user": user,
            "spn": spn,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = [
            "impacket-ticketer",
            "-domain", params["domain"],
            "-domain-sid", params["domain_sid"],
            "-nthash", params["nthash"],
        ]
        if params["spn"]:
            cmd.extend(["-spn", params["spn"]])
        cmd.append(params["user"])
        cmd.extend(params["tokens"])
        return cmd
