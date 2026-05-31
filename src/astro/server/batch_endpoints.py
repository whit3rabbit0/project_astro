"""Batch and parallel execution MCP tool endpoints."""
from __future__ import annotations

from typing import Any, Awaitable, Callable, Optional

import structlog

from astro.core.parallel import BatchResult, ParallelExecutor, ToolTask
from astro.tools.base import BaseTool, ToolResult
from astro.tools.registry import ToolRegistry

logger = structlog.get_logger(__name__)


def register_batch_tools(
    mcp: Any,
    run_tool_fn: Callable[..., Awaitable[dict[str, Any]]],
    registry: ToolRegistry,
    executor: Any,
) -> None:
    """Register batch execution MCP tools on the given FastMCP server."""

    @mcp.tool()
    async def batch_execute(
        tools: list[dict[str, Any]],
        max_concurrent: int = 5,
    ) -> dict[str, Any]:
        """Execute multiple tools in parallel and return aggregated results.

        Args:
            tools: List of tool invocations, each with 'tool' (name) and 'params' (dict).
                   Example: [{"tool": "nmap", "params": {"target": "10.10.10.10"}},
                             {"tool": "gobuster", "params": {"url": "http://10.10.10.10"}}]
            max_concurrent: Maximum simultaneous tool executions (1-10, default: 5).
        """
        max_concurrent = max(1, min(10, max_concurrent))

        tasks = []
        for item in tools:
            tool_name = item.get("tool", "")
            params = item.get("params", {})
            if not tool_name:
                continue
            tasks.append(ToolTask(tool_key=tool_name, params=params))

        if not tasks:
            return {"status": "error", "message": "No valid tool invocations provided"}

        parallel = ParallelExecutor(max_concurrent=max_concurrent)
        result: BatchResult = await parallel.execute_batch(
            tasks=tasks,
            tool_resolver=registry.get,
            executor=executor,
        )

        return {
            "status": "ok",
            "total": result.total,
            "succeeded": result.succeeded,
            "failed": result.failed,
            "duration_ms": result.duration_ms,
            "results": [r.model_dump() for r in result.results],
            "errors": [e.model_dump() for e in result.errors],
        }

    @mcp.tool()
    async def batch_nmap(
        targets: list[str],
        scan_type: str = "-sV",
        ports: str = "",
        additional_args: str = "",
        max_concurrent: int = 3,
    ) -> dict[str, Any]:
        """Run nmap against multiple targets in parallel.

        Args:
            targets: List of target IPs, hostnames, or CIDR ranges.
            scan_type: Nmap scan flags applied to all targets (default: -sV).
            ports: Port specification applied to all targets (e.g. '80,443').
            additional_args: Extra nmap flags applied to all targets.
            max_concurrent: Maximum simultaneous nmap scans (1-5, default: 3).
        """
        max_concurrent = max(1, min(5, max_concurrent))

        tasks = [
            ToolTask(
                tool_key="nmap",
                params={
                    "target": target,
                    "scan_type": scan_type,
                    "ports": ports,
                    "additional_args": additional_args,
                },
            )
            for target in targets
        ]

        if not tasks:
            return {"status": "error", "message": "No targets provided"}

        parallel = ParallelExecutor(max_concurrent=max_concurrent)
        result: BatchResult = await parallel.execute_batch(
            tasks=tasks,
            tool_resolver=registry.get,
            executor=executor,
        )

        return {
            "status": "ok",
            "total": result.total,
            "succeeded": result.succeeded,
            "failed": result.failed,
            "duration_ms": result.duration_ms,
            "results": [r.model_dump() for r in result.results],
            "errors": [e.model_dump() for e in result.errors],
        }
