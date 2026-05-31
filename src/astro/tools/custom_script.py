"""Custom script executor — write and run arbitrary Python or Bash scripts."""
import os
import tempfile
from typing import Any

from astro.tools.base import BaseTool, ToolResult

_ALLOWED_LANGUAGES = frozenset({"bash", "python"})


class CustomScriptTool(BaseTool):
    name = "custom_script"
    description = "Execute a custom Python or Bash script. Full shell access for maximum flexibility."

    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        script = params.get("script", "")
        if not script:
            raise ValueError("Script content is required")

        language = params.get("language", "bash")
        if language not in _ALLOWED_LANGUAGES:
            raise ValueError("Language must be 'bash' or 'python'")

        timeout = params.get("timeout", 120)
        if not isinstance(timeout, int) or timeout < 1 or timeout > 600:
            raise ValueError("Timeout must be between 1 and 600 seconds")

        return {"script": script, "language": language, "timeout": timeout}

    def build_command(self, params: dict[str, Any]) -> list[str]:
        # Not used directly — execute() handles script writing and dispatch.
        return []

    async def execute(self, executor: Any, params: dict[str, Any]) -> ToolResult:
        """Write the script to a temp file and execute it via the appropriate interpreter."""
        validated = self.validate(params)
        script: str = validated["script"]
        language: str = validated["language"]
        timeout: int = validated["timeout"]

        suffix = ".py" if language == "python" else ".sh"
        fd, script_path = tempfile.mkstemp(suffix=suffix, prefix="astro_script_")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(script)
            os.chmod(script_path, 0o700)

            cmd = ["python3", script_path] if language == "python" else ["bash", script_path]
            raw = await executor.execute(cmd, timeout=timeout)
            return ToolResult(
                tool=self.name,
                target="custom_script",
                success=raw["success"],
                raw=raw,
                parsed=None,
            )
        finally:
            try:
                os.remove(script_path)
            except OSError:
                pass
