"""Job model for the v1.0 execution foundation (experimental)."""

from __future__ import annotations

import datetime as _dt
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ABANDONED = "abandoned"


def _now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).isoformat(timespec="seconds")


@dataclass
class Job:
    """A unit of work.

    ``payload`` is a free-form JSON-serializable dict. ``kind`` is the
    string key into the handler registry (see
    :func:`register_handler`).
    """

    id: str
    kind: str
    payload: dict[str, Any]
    status: str = JobStatus.QUEUED
    attempts: int = 0
    max_attempts: int = 3
    error: str | None = None
    created_at: str = field(default_factory=_now)
    started_at: str | None = None
    finished_at: str | None = None


def new_job(kind: str, payload: dict[str, Any], *, max_attempts: int = 3) -> Job:
    """Construct a fresh :class:`Job`."""
    return Job(
        id=str(uuid.uuid4()),
        kind=kind,
        payload=dict(payload),
        max_attempts=max_attempts,
    )
