"""Queue abstraction (v1.0, experimental)."""

from __future__ import annotations

from typing import Protocol

from .jobs import Job, JobStatus


class Queue(Protocol):
    """The minimum queue interface Drake-X assumes.

    A future remote implementation (Redis, SQS, ...) can plug in by
    satisfying this protocol. v1.0 only ships :class:`LocalQueue`.
    """

    def enqueue(self, job: Job) -> None: ...
    def dequeue(self) -> Job | None: ...
    def mark_running(self, job: Job) -> None: ...
    def mark_done(self, job: Job, *, error: str | None = None) -> None: ...


class LocalQueue:
    """SQLite-backed FIFO queue persisted alongside the workspace.

    Safe for a single writer / single worker. Enough to exercise the
    abstraction and persist job history for audit. No distributed
    safety guarantees are claimed.
    """

    def __init__(self, storage) -> None:
        self.storage = storage

    # --- Queue protocol ------------------------------------------------

    def enqueue(self, job: Job) -> None:
        self.storage.enqueue_job(job)

    def dequeue(self) -> Job | None:
        rows = self.storage.load_jobs(status=JobStatus.QUEUED, limit=1)
        if not rows:
            return None
        return _row_to_job(rows[0])

    def mark_running(self, job: Job) -> None:
        import datetime as _dt
        job.status = JobStatus.RUNNING
        job.attempts += 1
        job.started_at = _dt.datetime.now(tz=_dt.timezone.utc).isoformat(timespec="seconds")
        self.storage.update_job(job)

    def mark_done(self, job: Job, *, error: str | None = None) -> None:
        import datetime as _dt
        job.finished_at = _dt.datetime.now(tz=_dt.timezone.utc).isoformat(timespec="seconds")
        if error is None:
            job.status = JobStatus.SUCCEEDED
            job.error = None
        elif job.attempts >= job.max_attempts:
            job.status = JobStatus.ABANDONED
            job.error = error
        else:
            # Retryable failure — requeue.
            job.status = JobStatus.QUEUED
            job.error = error
        self.storage.update_job(job)


def _row_to_job(row: dict) -> Job:
    import json
    return Job(
        id=row["id"],
        kind=row["kind"],
        payload=json.loads(row["payload_json"]) if row.get("payload_json") else {},
        status=row["status"],
        attempts=int(row["attempts"]),
        max_attempts=int(row["max_attempts"]),
        error=row.get("error"),
        created_at=row["created_at"],
        started_at=row.get("started_at"),
        finished_at=row.get("finished_at"),
    )
