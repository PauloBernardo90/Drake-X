"""Lightweight console state persistence.

Stores the active workspace, session, last sample path, and last run
directory in ``~/.drake-x/state.json``. This state is:

- non-authoritative (workspace/session DB is the source of truth)
- safe to delete (console resumes with no context)
- small (one JSON file, no DB)
- resilient to corruption (returns defaults on any parse error)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..utils.pathing import expand_user_path

_STATE_PATH = expand_user_path("~/.drake-x/state.json")


@dataclass
class ConsoleState:
    """Active investigation context persisted between console sessions."""

    current_workspace: str = ""
    current_session: str = ""
    last_sample_path: str = ""
    last_run_dir: str = ""


def load_state() -> ConsoleState:
    """Load console state from disk. Returns defaults if missing or corrupt."""
    try:
        if _STATE_PATH.exists():
            data = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
            return ConsoleState(
                current_workspace=data.get("current_workspace", ""),
                current_session=data.get("current_session", ""),
                last_sample_path=data.get("last_sample_path", ""),
                last_run_dir=data.get("last_run_dir", ""),
            )
    except (json.JSONDecodeError, OSError, TypeError, KeyError):
        pass
    return ConsoleState()


def save_state(state: ConsoleState) -> None:
    """Persist console state to disk."""
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STATE_PATH.write_text(
        json.dumps(asdict(state), indent=2) + "\n",
        encoding="utf-8",
    )


def clear_state() -> None:
    """Remove persisted state file."""
    try:
        _STATE_PATH.unlink(missing_ok=True)
    except OSError:
        pass
