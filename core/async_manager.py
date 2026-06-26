"""AsyncManager — concurrent task execution with semaphore rate limiting,
exponential backoff, and per-task timeouts.

Replaces raw ThreadPoolExecutor loops where true async I/O is needed
(LLM API calls, RPC reads). ThreadPoolExecutor remains for CPU-bound work
(parallel regex scoring across M5 Max cores).

Usage:
    from core.async_manager import AsyncManager, run_concurrent

    async def audit_fn(fn_body: str) -> list:
        ...

    results = await run_concurrent(
        tasks=[audit_fn(body) for body in function_bodies],
        max_concurrent=4,
        timeout_seconds=60,
    )
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, List, Optional, TypeVar

T = TypeVar("T")

# Exponential backoff: delay = base * 2^attempt, capped at max_delay
_BASE_DELAY   = 1.0   # seconds
_MAX_DELAY    = 32.0  # seconds cap
_MAX_RETRIES  = 3


def _backoff(attempt: int) -> float:
    """Return wait time in seconds for attempt number (0-indexed)."""
    return min(_BASE_DELAY * (2 ** attempt), _MAX_DELAY)


async def _with_retry(
    coro: Awaitable[T],
    task_name: str = "",
    max_retries: int = _MAX_RETRIES,
    timeout: float = 60.0,
    retryable: tuple = (TimeoutError, ConnectionError, OSError),
) -> Optional[T]:
    """
    Run an awaitable with retry + exponential backoff.

    Returns None on exhausted retries instead of raising, so gather()
    can collect partial results without aborting the whole batch.
    """
    for attempt in range(max_retries + 1):
        try:
            return await asyncio.wait_for(coro if attempt == 0 else coro, timeout=timeout)
        except asyncio.TimeoutError:
            err_type = "TimeoutError"
            is_retryable = True
        except Exception as e:
            err_type = type(e).__name__
            is_retryable = isinstance(e, retryable) or any(
                k in str(e).lower() for k in ("rate_limit", "overloaded", "connection", "529")
            )

        if attempt < max_retries and is_retryable:
            wait = _backoff(attempt)
            print(f"  [AsyncManager] {task_name} {err_type} — retry {attempt+1}/{max_retries} in {wait:.1f}s")
            await asyncio.sleep(wait)
        else:
            print(f"  [AsyncManager] {task_name} failed after {attempt+1} attempt(s): {err_type}")
            return None

    return None


async def run_concurrent(
    tasks: List[Awaitable[T]],
    max_concurrent: int = 4,
    timeout_seconds: float = 60.0,
    task_names: Optional[List[str]] = None,
) -> List[T]:
    """
    Run a list of awaitables concurrently, bounded by a semaphore.

    Args:
        tasks:           List of coroutines/awaitables to run
        max_concurrent:  Max tasks in flight simultaneously
        timeout_seconds: Per-task timeout
        task_names:      Optional labels for logging

    Returns:
        List of results (None entries for failed tasks are filtered out)
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    names = task_names or [f"task-{i}" for i in range(len(tasks))]

    async def bounded(coro: Awaitable[T], name: str) -> Optional[T]:
        async with semaphore:
            return await _with_retry(coro, task_name=name, timeout=timeout_seconds)

    results = await asyncio.gather(
        *[bounded(t, n) for t, n in zip(tasks, names)],
        return_exceptions=False,
    )
    return [r for r in results if r is not None]


class AsyncManager:
    """
    Reusable concurrency manager for audit pipeline tasks.

    Wraps run_concurrent() with configurable limits and exposes
    a sync entry point for callers that can't use async directly.
    """

    def __init__(
        self,
        max_concurrent: int = 4,
        timeout_seconds: float = 60.0,
        max_retries: int = _MAX_RETRIES,
    ):
        self.max_concurrent  = max_concurrent
        self.timeout_seconds = timeout_seconds
        self.max_retries     = max_retries
        self._stats: dict    = {"submitted": 0, "succeeded": 0, "failed": 0}

    async def gather(
        self,
        tasks: List[Awaitable[T]],
        names: Optional[List[str]] = None,
    ) -> List[T]:
        """Async entry: run tasks and return results."""
        self._stats["submitted"] += len(tasks)
        t0 = time.monotonic()
        results = await run_concurrent(
            tasks,
            max_concurrent=self.max_concurrent,
            timeout_seconds=self.timeout_seconds,
            task_names=names,
        )
        self._stats["succeeded"] += len(results)
        self._stats["failed"]    += len(tasks) - len(results)
        elapsed = time.monotonic() - t0
        print(f"[AsyncManager] {len(results)}/{len(tasks)} tasks completed in {elapsed:.1f}s")
        return results

    def run(self, tasks: List[Awaitable[T]], names: Optional[List[str]] = None) -> List[T]:
        """Sync entry: runs an event loop for callers that aren't async."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Already inside an event loop (e.g., Jupyter) — use run_until_complete
                import concurrent.futures
                future = asyncio.ensure_future(self.gather(tasks, names))
                loop.run_until_complete(future)
                return future.result()
        except RuntimeError:
            pass
        return asyncio.run(self.gather(tasks, names))

    @property
    def stats(self) -> dict:
        return dict(self._stats)
