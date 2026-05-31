"""Abstract base class for all Kali tools."""
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel


class ToolResult(BaseModel):
    tool: str
    target: str
    success: bool
    raw: dict[str, Any]
    parsed: dict[str, Any] | None = None


class BaseTool(ABC):
    name: str
    description: str

    @abstractmethod
    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Validate and normalize input parameters. Raise ValueError on invalid input."""
        ...

    @abstractmethod
    def build_command(self, params: dict[str, Any]) -> list[str]:
        """Build subprocess argument list from validated params."""
        ...

    async def execute(self, executor: Any, params: dict[str, Any]) -> ToolResult:
        """Validate, build command, execute, and parse output.

        executor must satisfy: await executor.execute(cmd) -> dict with keys
        stdout, stderr, return_code, success.
        """
        validated = self.validate(params)
        cmd = self.build_command(validated)
        raw = await executor.execute(cmd)
        parsed = self.parse_output(raw, validated)
        target = validated.get("target", validated.get("url", "unknown"))
        return ToolResult(
            tool=self.name,
            target=target,
            success=raw["success"],
            raw=raw,
            parsed=parsed,
        )

    def parse_output(self, raw: dict[str, Any], params: dict[str, Any]) -> dict[str, Any] | None:
        """Override in subclasses to parse structured output. Default returns None."""
        return None
