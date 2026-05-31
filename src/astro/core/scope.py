import fnmatch
import ipaddress
import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import yaml


class ScopeViolationError(Exception):
    pass


_SMB_RE = re.compile(r"^//([^/]+)")


class ScopeEnforcer:
    def __init__(self, config_path: Optional[str] = None) -> None:
        self._config: Dict[str, Any] = {}
        if config_path is not None:
            with open(config_path, "r") as fh:
                self._config = yaml.safe_load(fh) or {}

    def _scope(self) -> Dict[str, Any]:
        return self._config.get("scope", {})

    @staticmethod
    def _extract_host(target: str) -> str:
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        m = _SMB_RE.match(target)
        if m:
            return m.group(1)
        host = target.split(":")[0]
        return host

    def validate_target(self, target: str) -> None:
        """Raise ScopeViolationError if target is out of scope."""
        scope = self._scope()
        if not scope:
            return

        host = self._extract_host(target)

        excluded = scope.get("excluded_targets", [])
        if target in excluded or host in excluded:
            raise ScopeViolationError(f"Target {target!r} is explicitly excluded")

        allowed_cidrs: list[str] = scope.get("allowed_cidrs", [])
        allowed_domains: list[str] = scope.get("allowed_domains", [])

        if not allowed_cidrs and not allowed_domains:
            return

        for cidr in allowed_cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                addr = ipaddress.ip_address(host)
                if addr in network:
                    return
            except ValueError:
                continue

        host_lower = host.lower()
        for pattern in allowed_domains:
            if fnmatch.fnmatch(host_lower, pattern.lower()):
                return

        raise ScopeViolationError(f"Target {target!r} is not in scope")

    def get_tool_restrictions(self, tool_name: str) -> Dict[str, Any]:
        """Return tool-specific restrictions from config, or empty dict."""
        return self._scope().get("tool_restrictions", {}).get(tool_name, {})
