"""Burp Suite Pro REST API integration tool."""
from typing import Any

import httpx

from astro.core.validators import validate_url
from astro.tools.base import BaseTool, ToolResult


_VALID_ACTIONS = frozenset({"scan", "status", "findings"})


class BurpTool(BaseTool):
    name = "burp"
    description = "Burp Suite Pro REST API integration for scanning and issue retrieval"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        action = params.get("action", "")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"action must be one of: {', '.join(sorted(_VALID_ACTIONS))}")

        target_url = params.get("target_url", "")
        scan_id = params.get("scan_id", "")
        burp_api_url = params.get("burp_api_url", "http://127.0.0.1:1337").rstrip("/")

        if action == "scan":
            if not target_url:
                raise ValueError("target_url is required for scan action")
            if not validate_url(target_url):
                raise ValueError("Invalid target_url: must be http/https with no shell metacharacters")

        if action in {"status", "findings"}:
            if not scan_id:
                raise ValueError(f"scan_id is required for {action} action")
            if not all(c.isalnum() or c in "-_" for c in scan_id):
                raise ValueError("Invalid scan_id parameter")

        return {
            "action": action,
            "target_url": target_url,
            "scan_id": scan_id,
            "burp_api_url": burp_api_url,
        }

    def build_command(self, params: dict[str, Any]) -> list[str]:
        # BurpTool uses httpx, not subprocess — this method is not used.
        return []

    async def execute(self, executor: Any, params: dict[str, Any]) -> ToolResult:
        validated = self.validate(params)
        action = validated["action"]
        api_url = validated["burp_api_url"]

        async with httpx.AsyncClient(timeout=30.0) as client:
            if action == "scan":
                return await self._do_scan(client, api_url, validated)
            if action == "status":
                return await self._do_status(client, api_url, validated)
            return await self._do_findings(client, api_url, validated)

    async def _do_scan(self, client: httpx.AsyncClient, api_url: str, params: dict[str, Any]) -> ToolResult:
        target_url = params["target_url"]
        try:
            response = await client.post(
                f"{api_url}/v0.1/scan",
                json={"urls": [target_url]},
            )
            raw_dict: dict[str, Any] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
            }
            success = response.status_code in (201, 200)
            scan_id = ""
            location = response.headers.get("location", "")
            if location:
                scan_id = location.rstrip("/").split("/")[-1]
            parsed: dict[str, Any] = {"scan_id": scan_id, "target_url": target_url}
            return ToolResult(tool=self.name, target=target_url, success=success, raw=raw_dict, parsed=parsed)
        except httpx.HTTPError as exc:
            raw_err: dict[str, Any] = {"error": str(exc)}
            return ToolResult(tool=self.name, target=target_url, success=False, raw=raw_err, parsed=None)

    async def _do_status(self, client: httpx.AsyncClient, api_url: str, params: dict[str, Any]) -> ToolResult:
        scan_id = params["scan_id"]
        try:
            response = await client.get(f"{api_url}/v0.1/scan/{scan_id}")
            raw_dict = {"status_code": response.status_code, "body": response.json() if response.content else {}}
            success = response.status_code == 200
            parsed = raw_dict["body"] if success else {}
            return ToolResult(tool=self.name, target=scan_id, success=success, raw=raw_dict, parsed=parsed)
        except httpx.HTTPError as exc:
            raw_err = {"error": str(exc)}
            return ToolResult(tool=self.name, target=scan_id, success=False, raw=raw_err, parsed=None)

    async def _do_findings(self, client: httpx.AsyncClient, api_url: str, params: dict[str, Any]) -> ToolResult:
        scan_id = params["scan_id"]
        try:
            response = await client.get(f"{api_url}/v0.1/scan/{scan_id}/issues")
            success = response.status_code == 200
            body: Any = response.json() if response.content else {}
            raw_dict: dict[str, Any] = {"status_code": response.status_code, "body": body}
            parsed = self._parse_issues(body) if success else {"issues": [], "count": 0}
            return ToolResult(tool=self.name, target=scan_id, success=success, raw=raw_dict, parsed=parsed)
        except httpx.HTTPError as exc:
            raw_err = {"error": str(exc)}
            return ToolResult(tool=self.name, target=scan_id, success=False, raw=raw_err, parsed=None)

    def _parse_issues(self, body: Any) -> dict[str, Any]:
        issues_raw = body if isinstance(body, list) else body.get("issues", [])
        issues = [
            {
                "name": issue.get("name", ""),
                "severity": issue.get("severity", ""),
                "confidence": issue.get("confidence", ""),
                "url": issue.get("origin", issue.get("url", "")),
                "description": issue.get("issueBackground", issue.get("description", "")),
            }
            for issue in issues_raw
            if isinstance(issue, dict)
        ]
        return {"issues": issues, "count": len(issues)}

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        return None
