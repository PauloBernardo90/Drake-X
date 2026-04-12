"""Local synchronous worker (v1.0, experimental)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..logging import get_logger
from .jobs import Job
from .queue import Queue

log = get_logger("execution.worker")

# Handler registry: ``kind`` → callable(payload: dict) -> None.
_HANDLERS: dict[str, Callable[[dict[str, Any]], None]] = {}


def register_handler(kind: str):
    """Decorator: register a handler for jobs of ``kind``."""

    def _wrap(fn: Callable[[dict[str, Any]], None]):
        if kind in _HANDLERS:
            raise ValueError(f"handler for kind '{kind}' already registered")
        _HANDLERS[kind] = fn
        return fn

    return _wrap


def registered_handlers() -> dict[str, Callable[[dict[str, Any]], None]]:
    return dict(_HANDLERS)


class LocalWorker:
    """Drain a :class:`Queue` synchronously, one job at a time."""

    def __init__(self, queue: Queue) -> None:
        self.queue = queue

    def run_once(self) -> Job | None:
        """Process a single queued job. Returns the processed ``Job`` or ``None``."""
        job = self.queue.dequeue()
        if job is None:
            return None
        self.queue.mark_running(job)
        handler = _HANDLERS.get(job.kind)
        if handler is None:
            # Missing-handler is a non-transient error; force attempts to
            # max so ``mark_done`` abandons rather than re-queuing.
            job.attempts = job.max_attempts
            self.queue.mark_done(job, error=f"no handler registered for kind '{job.kind}'")
            return job
        try:
            handler(job.payload)
            self.queue.mark_done(job)
        except Exception as exc:  # noqa: BLE001
            log.warning("job %s failed: %s", job.id, exc)
            self.queue.mark_done(job, error=str(exc))
        return job

    def drain(self, *, max_jobs: int = 100) -> int:
        """Drain up to ``max_jobs`` queued jobs. Returns how many were processed."""
        n = 0
        for _ in range(max_jobs):
            j = self.run_once()
            if j is None:
                break
            n += 1
        return n
