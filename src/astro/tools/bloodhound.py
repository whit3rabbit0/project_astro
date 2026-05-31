"""BloodHoundTool — AD attack path collection for BloodHound visualization."""
import re
from typing import Any

from astro.core.validators import SHELL_METACHARACTERS, validate_additional_args
from astro.tools.base import BaseTool

_HASHES_RE = re.compile(r'^[0-9a-fA-F:]+$')
_ZIP_RE = re.compile(r'(\S+\.zip)')

_VALID_COLLECTION_METHODS = {"all", "default", "group", "localadmin", "session", "trusts", "acl", "objectprops"}


class BloodHoundTool(BaseTool):
    name = "bloodhound"
    description = "AD attack path collection for BloodHound visualization"

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

        collection_method = params.get("collection_method", "all")
        if collection_method not in _VALID_COLLECTION_METHODS:
            raise ValueError(f"Invalid collection_method: must be one of {sorted(_VALID_COLLECTION_METHODS)}")

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
            "collection_method": collection_method,
            "tokens": tokens,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        cmd = [
            "bloodhound-python",
            "-d", params["domain"],
            "-u", params["username"],
            "-dc", params["target"],
            "-c", params["collection_method"],
            "--zip",
        ]
        if params["hashes"]:
            cmd.extend(["--hashes", params["hashes"]])
        else:
            cmd.extend(["-p", params["password"]])
        cmd.extend(params["tokens"])
        return cmd

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        stdout = raw.get("stdout", "")
        match = _ZIP_RE.search(stdout)
        return {
            "output_file": match.group(1) if match else None,
            "domain": params["domain"],
        }
