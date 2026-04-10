"""Time helpers.

UTC-only by design — local times in security tooling are a recipe for
ambiguous report timestamps. The few places that need a human-friendly local
time should format ``isoformat_utc`` themselves.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Return a tz-aware UTC datetime."""
    return datetime.now(UTC)


def isoformat_utc(dt: datetime | None) -> str | None:
    """Return ISO-8601 UTC string, or ``None`` if ``dt`` is None."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()
