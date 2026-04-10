"""Concurrency budget + per-host pacing.

Drake-X needs two related controls:

1. A *global* concurrency budget (no more than N integrations running at
   once across the engine).
2. A *per-host* request rate limit (no more than R requests per second per
   target host).

Both are implemented as small async primitives that integrations can opt
into. The default :class:`BaseTool` does not currently honor (2) — that
will land in the next refactor pass when each integration declares its
HTTP-style request count.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class RateLimiter:
    """Token-bucket-style per-host limiter plus a global semaphore."""

    def __init__(self, *, max_concurrency: int, per_host_rps: float) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        if per_host_rps <= 0:
            raise ValueError("per_host_rps must be > 0")
        self._global = asyncio.Semaphore(max_concurrency)
        self._per_host_rps = per_host_rps
        self._min_interval = 1.0 / per_host_rps
        self._last_call: dict[str, float] = defaultdict(float)
        self._host_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def acquire(self, host: str) -> None:
        """Block until both the global budget and per-host pacing allow a call."""
        await self._global.acquire()
        lock = self._host_locks[host]
        async with lock:
            now = time.monotonic()
            elapsed = now - self._last_call[host]
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_call[host] = time.monotonic()

    def release(self) -> None:
        self._global.release()

    # Convenience async-context-manager interface.
    def slot(self, host: str) -> "_RateLimitSlot":
        return _RateLimitSlot(self, host)


class _RateLimitSlot:
    def __init__(self, limiter: RateLimiter, host: str) -> None:
        self._limiter = limiter
        self._host = host

    async def __aenter__(self) -> None:
        await self._limiter.acquire(self._host)

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self._limiter.release()
