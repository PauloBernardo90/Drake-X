"""Append-only audit log.

Every action the engine plans, runs, denies or completes writes one JSON
line to ``<workspace>/audit.log``. The format is intentionally line-oriented
JSON so the file is grep-friendly and trivially parseable from shell.

The audit log is the operator's first defense against the question "what
did Drake-X actually do during this engagement?". It is *not* a replacement
for the SQLite session store — the audit log is the chronological journal
of intent and outcome, the SQLite store is the structured evidence database.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..utils.timefmt import isoformat_utc, utcnow


@dataclass
class AuditEvent:
    """One line in the audit log."""

    ts: str
    actor: str
    action: str
    subject: str
    dry_run: bool = False
    decision: str = "allow"
    workspace: str | None = None
    session_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def now(
        cls,
        *,
        actor: str,
        action: str,
        subject: str,
        decision: str = "allow",
        dry_run: bool = False,
        workspace: str | None = None,
        session_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> "AuditEvent":
        return cls(
            ts=isoformat_utc(utcnow()) or "",
            actor=actor,
            action=action,
            subject=subject,
            decision=decision,
            dry_run=dry_run,
            workspace=workspace,
            session_id=session_id,
            payload=payload or {},
        )

    def to_json_line(self) -> str:
        return json.dumps(asdict(self), default=str)


class AuditLog:
    """Append-only writer for ``<workspace>/audit.log``."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: AuditEvent) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(event.to_json_line() + "\n")

    def read_all(self) -> list[AuditEvent]:
        if not self.path.exists():
            return []
        events: list[AuditEvent] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(
                AuditEvent(
                    ts=data.get("ts", ""),
                    actor=data.get("actor", "?"),
                    action=data.get("action", "?"),
                    subject=data.get("subject", "?"),
                    decision=data.get("decision", "allow"),
                    dry_run=bool(data.get("dry_run", False)),
                    workspace=data.get("workspace"),
                    session_id=data.get("session_id"),
                    payload=data.get("payload") or {},
                )
            )
        return events


def _utcnow_str() -> str:
    return isoformat_utc(datetime.now()) or ""
