"""ID generators.

Stable, short identifiers for sessions and findings. We deliberately keep
these short because they appear in CLI output and Markdown reports.
"""

from __future__ import annotations

from uuid import uuid4


def new_session_id() -> str:
    """Return a 12-char session id derived from a v4 UUID."""
    return uuid4().hex[:12]


def new_finding_id() -> str:
    """Return a 10-char finding id derived from a v4 UUID."""
    return "f-" + uuid4().hex[:10]
