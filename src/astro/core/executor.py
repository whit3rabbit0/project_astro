import asyncio
import subprocess
import traceback
from typing import Dict, Any, List

import structlog

logger = structlog.get_logger(__name__)


class ToolExecutor:
    async def execute(self, command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Execute command in a thread pool and return stdout/stderr/return_code/success."""
        return await asyncio.to_thread(self._run, command, timeout)

    def _run(self, command: List[str], timeout: int) -> Dict[str, Any]:
        logger.info("executing_command", command=command)
        try:
            process = subprocess.Popen(
                command,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(timeout=timeout)
            return_code = process.returncode
            logger.debug("command_complete", return_code=return_code)
            return {
                "stdout": stdout,
                "stderr": stderr,
                "return_code": return_code,
                "success": return_code == 0,
            }
        except subprocess.TimeoutExpired:
            logger.error("command_timeout", timeout=timeout)
            return {
                "stdout": "",
                "stderr": f"Command execution timed out after {timeout} seconds",
                "return_code": -1,
                "success": False,
            }
        except Exception as exc:
            logger.error("command_error", error=str(exc), traceback=traceback.format_exc())
            return {
                "stdout": "",
                "stderr": f"Error executing command: {exc}",
                "return_code": -1,
                "success": False,
            }
