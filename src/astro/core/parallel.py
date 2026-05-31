"""Parallel and batch tool execution engine."""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Awaitable, Callable, Optional

import structlog
from pydantic import BaseModel, Field

from astro.tools.base import BaseTool, ToolResult

logger = structlog.get_logger(__name__)


class ToolTask(BaseModel):
    tool_key: str
    params: dict[str, Any]
    task_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])


class ToolError(BaseModel):
    tool_key: str
    task_id: str
    error: str


class BatchResult(BaseModel):
    total: int
    succeeded: int
    failed: int
    results: list[ToolResult]
    errors: list[ToolError]
    duration_ms: int


class ParallelExecutor:
    """Executes multiple tools concurrently with result aggregation."""

    def __init__(self, max_concurrent: int = 5) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def execute_parallel(
        self,
        tasks: list[ToolTask],
        tool_resolver: Callable[[str], BaseTool],
        executor: Any,
    ) -> list[ToolResult | ToolError]:
        async def _run_one(task: ToolTask) -> ToolResult | ToolError:
            async with self._semaphore:
                try:
                    tool = tool_resolver(task.tool_key)
                    result = await tool.execute(executor, task.params)
                    logger.info("parallel_task_complete", task_id=task.task_id, tool=task.tool_key, success=result.success)
                    return result
                except Exception as exc:
                    logger.error("parallel_task_failed", task_id=task.task_id, tool=task.tool_key, error=str(exc))
                    return ToolError(tool_key=task.tool_key, task_id=task.task_id, error=str(exc))

        coros = [_run_one(task) for task in tasks]
        return await asyncio.gather(*coros)

    async def execute_batch(
        self,
        tasks: list[ToolTask],
        tool_resolver: Callable[[str], BaseTool],
        executor: Any,
        on_complete: Optional[Callable[[ToolTask, ToolResult], Awaitable[None]]] = None,
    ) -> BatchResult:
        start = time.monotonic()

        async def _run_one(task: ToolTask) -> ToolResult | ToolError:
            async with self._semaphore:
                try:
                    tool = tool_resolver(task.tool_key)
                    result = await tool.execute(executor, task.params)
                    if on_complete and isinstance(result, ToolResult):
                        await on_complete(task, result)
                    return result
                except Exception as exc:
                    return ToolError(tool_key=task.tool_key, task_id=task.task_id, error=str(exc))

        raw_results = await asyncio.gather(*[_run_one(t) for t in tasks])

        results: list[ToolResult] = []
        errors: list[ToolError] = []
        for r in raw_results:
            if isinstance(r, ToolError):
                errors.append(r)
            else:
                results.append(r)

        duration_ms = int((time.monotonic() - start) * 1000)

        logger.info(
            "batch_complete",
            total=len(tasks),
            succeeded=len(results),
            failed=len(errors),
            duration_ms=duration_ms,
        )

        return BatchResult(
            total=len(tasks),
            succeeded=len(results),
            failed=len(errors),
            results=results,
            errors=errors,
            duration_ms=duration_ms,
        )
