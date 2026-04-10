"""Path helpers.

We mostly need a tiny ``~`` expander and a ``relative if possible`` helper
for nicer report output.
"""

from __future__ import annotations

from pathlib import Path


def expand_user_path(value: str | Path) -> Path:
    """Expand ``~`` and return an absolute :class:`Path`."""
    return Path(value).expanduser().resolve()


def safe_relative(path: Path, base: Path) -> Path:
    """Return ``path`` relative to ``base`` when possible, else absolute.

    Used by reports so we can show ``runs/<sid>/report.md`` rather than the
    full machine-specific absolute path.
    """
    try:
        return path.resolve().relative_to(base.resolve())
    except ValueError:
        return path.resolve()
