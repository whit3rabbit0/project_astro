import collections
from typing import Any, Dict


class MetricsTracker:
    def __init__(self) -> None:
        self._executions: collections.deque[Dict[str, Any]] = collections.deque(maxlen=1000)

    def record_tool_execution(
        self,
        tool: str,
        target: str,
        duration: float,
        success: bool,
    ) -> None:
        self._executions.append(
            {"tool": tool, "target": target, "duration": duration, "success": success}
        )

    def get_summary(self) -> Dict[str, Any]:
        """Return counts by tool, success rate, and average duration."""
        if not self._executions:
            return {"total": 0, "by_tool": {}, "success_rate": None, "avg_duration": None}

        total = len(self._executions)
        by_tool: Dict[str, int] = {}
        successes = 0
        total_duration = 0.0

        for entry in self._executions:
            by_tool[entry["tool"]] = by_tool.get(entry["tool"], 0) + 1
            if entry["success"]:
                successes += 1
            total_duration += entry["duration"]

        return {
            "total": total,
            "by_tool": by_tool,
            "success_rate": successes / total,
            "avg_duration": total_duration / total,
        }
