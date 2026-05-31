"""LinPEAS privilege escalation enumeration tool."""
from typing import Any

from astro.core.validators import validate_additional_args, validate_path
from astro.tools.base import BaseTool, ToolResult


_VALID_MODES = frozenset({"local", "generate"})
_LINPEAS_CURL_ONELINER = (
    "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh"
)


class LinpeasTool(BaseTool):
    name = "linpeas"
    description = "Linux privilege escalation enumeration script"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        mode = params.get("mode", "local")
        if mode not in _VALID_MODES:
            raise ValueError(f"mode must be one of: {', '.join(sorted(_VALID_MODES))}")

        linpeas_path = params.get("linpeas_path", "/usr/share/peass/linpeas/linpeas.sh")
        if not validate_path(linpeas_path):
            raise ValueError("Invalid linpeas_path: must be an absolute path with safe characters")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"mode": mode, "linpeas_path": linpeas_path, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        return ["bash", params["linpeas_path"], *params["tokens"]]

    async def execute(self, executor: Any, params: dict[str, Any]) -> ToolResult:
        validated = self.validate(params)

        if validated["mode"] == "generate":
            return ToolResult(
                tool=self.name,
                target="generate",
                success=True,
                raw={"stdout": _LINPEAS_CURL_ONELINER, "stderr": "", "return_code": 0, "success": True},
                parsed={"command": _LINPEAS_CURL_ONELINER, "mode": "generate"},
            )

        cmd = self.build_command(validated)
        raw = await executor.execute(cmd)
        return ToolResult(
            tool=self.name,
            target=validated["linpeas_path"],
            success=raw["success"],
            raw=raw,
            parsed=self.parse_output(raw, validated),
        )

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        return {"mode": params["mode"], "linpeas_path": params["linpeas_path"]}
