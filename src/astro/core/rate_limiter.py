"""Per-tool rate limiting with concurrency control."""
from __future__ import annotations

import asyncio
import contextlib
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

import structlog

logger = structlog.get_logger(__name__)


class RateLimitExceeded(Exception):
    """Raised when a tool invocation exceeds the configured rate limit."""


@dataclass
class _ToolConfig:
    max_concurrent: int = 3
    rate_limit: int = 10
    rate_window: int = 60


@dataclass
class _ToolMetrics:
    active: int = 0
    total: int = 0
    rejected: int = 0
    total_wait_ms: float = 0.0
    max_wait_ms: float = 0.0


class _TokenBucket:
    """Async token bucket with continuous refill."""

    def __init__(self, capacity: int, refill_rate: float) -> None:
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False

            wait = min(1.0 / self._refill_rate if self._refill_rate > 0 else 1.0, remaining)
            await asyncio.sleep(wait)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._refill_rate)
        self._last_refill = now


class RateLimiter:
    """Per-tool and global rate limiting with concurrency control.

    Usage::

        async with rate_limiter.acquire("nmap"):
            result = await tool.execute(executor, params)
    """

    def __init__(
        self,
        default_max_concurrent: int = 3,
        default_rate_limit: int = 10,
        default_rate_window: int = 60,
        global_max_concurrent: int = 30,
        tool_configs: dict[str, dict[str, Any]] | None = None,
        acquire_timeout: float = 120.0,
    ) -> None:
        self._default_config = _ToolConfig(
            max_concurrent=default_max_concurrent,
            rate_limit=default_rate_limit,
            rate_window=default_rate_window,
        )
        self._acquire_timeout = acquire_timeout
        self._global_semaphore = asyncio.Semaphore(global_max_concurrent)
        self._tool_configs: dict[str, _ToolConfig] = {}
        self._tool_semaphores: dict[str, asyncio.Semaphore] = {}
        self._tool_buckets: dict[str, _TokenBucket] = {}
        self._metrics: dict[str, _ToolMetrics] = defaultdict(_ToolMetrics)

        if tool_configs:
            for name, cfg in tool_configs.items():
                self.configure_tool(
                    name,
                    max_concurrent=cfg.get("max_concurrent", default_max_concurrent),
                    rate_limit=cfg.get("rate_limit", default_rate_limit),
                    rate_window=cfg.get("rate_window", default_rate_window),
                )

    def configure_tool(
        self,
        tool_name: str,
        max_concurrent: int = 3,
        rate_limit: int = 10,
        rate_window: int = 60,
    ) -> None:
        self._tool_configs[tool_name] = _ToolConfig(
            max_concurrent=max_concurrent,
            rate_limit=rate_limit,
            rate_window=rate_window,
        )
        self._tool_semaphores[tool_name] = asyncio.Semaphore(max_concurrent)
        refill_rate = rate_limit / rate_window if rate_window > 0 else float("inf")
        self._tool_buckets[tool_name] = _TokenBucket(rate_limit, refill_rate)

    def _get_config(self, tool_name: str) -> _ToolConfig:
        return self._tool_configs.get(tool_name, self._default_config)

    def _get_semaphore(self, tool_name: str) -> asyncio.Semaphore:
        if tool_name not in self._tool_semaphores:
            cfg = self._get_config(tool_name)
            self._tool_semaphores[tool_name] = asyncio.Semaphore(cfg.max_concurrent)
        return self._tool_semaphores[tool_name]

    def _get_bucket(self, tool_name: str) -> _TokenBucket:
        if tool_name not in self._tool_buckets:
            cfg = self._get_config(tool_name)
            refill_rate = cfg.rate_limit / cfg.rate_window if cfg.rate_window > 0 else float("inf")
            self._tool_buckets[tool_name] = _TokenBucket(cfg.rate_limit, refill_rate)
        return self._tool_buckets[tool_name]

    @contextlib.asynccontextmanager
    async def acquire(self, tool_name: str) -> AsyncIterator[None]:
        metrics = self._metrics[tool_name]
        start = time.monotonic()
        timeout_remaining = self._acquire_timeout

        bucket = self._get_bucket(tool_name)
        if not await bucket.acquire(timeout_remaining):
            metrics.rejected += 1
            logger.warning("rate_limit_exceeded", tool=tool_name, reason="token_bucket")
            raise RateLimitExceeded(f"Rate limit exceeded for tool {tool_name!r}")

        timeout_remaining -= time.monotonic() - start

        tool_sem = self._get_semaphore(tool_name)
        try:
            acquired = await asyncio.wait_for(tool_sem.acquire(), timeout=max(timeout_remaining, 0))
        except asyncio.TimeoutError:
            metrics.rejected += 1
            logger.warning("rate_limit_exceeded", tool=tool_name, reason="tool_concurrency")
            raise RateLimitExceeded(f"Concurrency limit exceeded for tool {tool_name!r}")

        timeout_remaining -= time.monotonic() - start

        try:
            try:
                await asyncio.wait_for(self._global_semaphore.acquire(), timeout=max(timeout_remaining, 0))
            except asyncio.TimeoutError:
                tool_sem.release()
                metrics.rejected += 1
                logger.warning("rate_limit_exceeded", tool=tool_name, reason="global_concurrency")
                raise RateLimitExceeded("Global concurrency limit exceeded")

            wait_ms = (time.monotonic() - start) * 1000
            metrics.total_wait_ms += wait_ms
            metrics.max_wait_ms = max(metrics.max_wait_ms, wait_ms)
            metrics.active += 1
            metrics.total += 1

            logger.debug("rate_limit_acquired", tool=tool_name, wait_ms=round(wait_ms, 1))

            try:
                yield
            finally:
                metrics.active -= 1
                self._global_semaphore.release()
        finally:
            tool_sem.release()

    def get_metrics(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for tool_name, m in self._metrics.items():
            avg_wait = m.total_wait_ms / m.total if m.total > 0 else 0.0
            result[tool_name] = {
                "active": m.active,
                "total": m.total,
                "rejected": m.rejected,
                "avg_wait_ms": round(avg_wait, 1),
                "max_wait_ms": round(m.max_wait_ms, 1),
            }
        return result
