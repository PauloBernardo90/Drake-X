"""SQLite persistence for sessions, tool results, artifacts, and findings.

We keep the schema deliberately simple: a single table per concept, JSON
blobs for variable-shaped data. The schema is created on first use; there
are no migrations because there's nothing to migrate yet.

If you ever need to evolve the schema, prefer additive changes and bump
``SCHEMA_VERSION`` so consumers can detect the change.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .exceptions import StorageError
from .logging import get_logger
from .models.artifact import Artifact
from .models.finding import Finding
from .models.session import Session, SessionStatus
from .models.target import Target
from .models.tool_result import ToolResult, ToolResultStatus

log = get_logger("store")

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    target_json TEXT NOT NULL,
    tools_planned TEXT NOT NULL,
    tools_ran TEXT NOT NULL,
    tools_skipped TEXT NOT NULL,
    warnings TEXT NOT NULL,
    ai_enabled INTEGER NOT NULL DEFAULT 0,
    ai_model TEXT,
    ai_summary TEXT,
    report_path TEXT
);

CREATE TABLE IF NOT EXISTS tool_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    command TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_seconds REAL,
    exit_code INTEGER,
    status TEXT NOT NULL,
    stdout TEXT,
    stderr TEXT,
    error_message TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    confidence REAL NOT NULL,
    notes TEXT NOT NULL,
    tool_status TEXT NOT NULL DEFAULT 'ok',
    exit_code INTEGER,
    degraded INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    related_tools TEXT NOT NULL,
    recommended_next_steps TEXT NOT NULL,
    caveats TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);
"""


class SessionStore:
    """Lightweight wrapper around a single SQLite database file."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ----- low-level ---------------------------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
                row = conn.execute("SELECT version FROM schema_meta").fetchone()
                if row is None:
                    conn.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
        except sqlite3.Error as exc:
            raise StorageError(f"failed to initialize SQLite schema: {exc}") from exc

    # ----- writes ------------------------------------------------------

    def save_session(self, session: Session) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO sessions (
                        id, profile, status, started_at, finished_at,
                        target_json, tools_planned, tools_ran, tools_skipped,
                        warnings, ai_enabled, ai_model, ai_summary, report_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        profile=excluded.profile,
                        status=excluded.status,
                        started_at=excluded.started_at,
                        finished_at=excluded.finished_at,
                        target_json=excluded.target_json,
                        tools_planned=excluded.tools_planned,
                        tools_ran=excluded.tools_ran,
                        tools_skipped=excluded.tools_skipped,
                        warnings=excluded.warnings,
                        ai_enabled=excluded.ai_enabled,
                        ai_model=excluded.ai_model,
                        ai_summary=excluded.ai_summary,
                        report_path=excluded.report_path
                    """,
                    (
                        session.id,
                        session.profile,
                        session.status.value,
                        session.started_at.isoformat(),
                        session.finished_at.isoformat() if session.finished_at else None,
                        session.target.model_dump_json(),
                        json.dumps(session.tools_planned),
                        json.dumps(session.tools_ran),
                        json.dumps(session.tools_skipped),
                        json.dumps(session.warnings),
                        1 if session.ai_enabled else 0,
                        session.ai_model,
                        session.ai_summary,
                        session.report_path,
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to persist session {session.id}: {exc}") from exc

    def save_tool_result(self, session_id: str, result: ToolResult) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO tool_results (
                        session_id, tool_name, command, started_at, finished_at,
                        duration_seconds, exit_code, status, stdout, stderr, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        result.tool_name,
                        json.dumps(result.command),
                        result.started_at.isoformat(),
                        result.finished_at.isoformat() if result.finished_at else None,
                        result.duration_seconds,
                        result.exit_code,
                        result.status.value,
                        result.stdout,
                        result.stderr,
                        result.error_message,
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to persist tool result for {result.tool_name}: {exc}") from exc

    def save_artifact(self, session_id: str, artifact: Artifact) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO artifacts (
                        session_id, tool_name, kind, payload_json, confidence, notes,
                        tool_status, exit_code, degraded
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        artifact.tool_name,
                        artifact.kind,
                        json.dumps(artifact.payload),
                        artifact.confidence,
                        json.dumps(artifact.notes),
                        artifact.tool_status,
                        artifact.exit_code,
                        1 if artifact.degraded else 0,
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to persist artifact {artifact.kind}: {exc}") from exc

    def save_finding(self, session_id: str, finding: Finding) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO findings (
                        session_id, title, summary, severity, confidence, source,
                        related_tools, recommended_next_steps, caveats
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        finding.title,
                        finding.summary,
                        finding.severity.value,
                        finding.confidence,
                        finding.source.value,
                        json.dumps(finding.related_tools),
                        json.dumps(finding.recommended_next_steps),
                        json.dumps(finding.caveats),
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to persist finding {finding.title!r}: {exc}") from exc

    # ----- reads -------------------------------------------------------

    def load_session(self, session_id: str) -> Session | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
            if row is None:
                return None
            return _row_to_session(row)

    def list_sessions(self, limit: int = 50) -> list[Session]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [_row_to_session(r) for r in rows]

    def load_tool_results(self, session_id: str) -> list[ToolResult]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tool_results WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            ).fetchall()
        results: list[ToolResult] = []
        for r in rows:
            results.append(
                ToolResult(
                    tool_name=r["tool_name"],
                    command=json.loads(r["command"]),
                    started_at=_parse_dt(r["started_at"]),
                    finished_at=_parse_dt(r["finished_at"]) if r["finished_at"] else None,
                    duration_seconds=r["duration_seconds"],
                    exit_code=r["exit_code"],
                    status=ToolResultStatus(r["status"]),
                    stdout=r["stdout"] or "",
                    stderr=r["stderr"] or "",
                    error_message=r["error_message"],
                )
            )
        return results

    def load_artifacts(self, session_id: str) -> list[Artifact]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM artifacts WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            ).fetchall()
        out: list[Artifact] = []
        for r in rows:
            keys = r.keys()
            out.append(
                Artifact(
                    tool_name=r["tool_name"],
                    kind=r["kind"],
                    payload=json.loads(r["payload_json"]),
                    confidence=r["confidence"],
                    notes=json.loads(r["notes"]),
                    tool_status=r["tool_status"] if "tool_status" in keys else "ok",
                    exit_code=r["exit_code"] if "exit_code" in keys else None,
                    degraded=bool(r["degraded"]) if "degraded" in keys else False,
                )
            )
        return out

    def load_findings(self, session_id: str) -> list[Finding]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            ).fetchall()
        out: list[Finding] = []
        for r in rows:
            out.append(
                Finding(
                    title=r["title"],
                    summary=r["summary"],
                    severity=r["severity"],
                    confidence=r["confidence"],
                    source=r["source"],
                    related_tools=json.loads(r["related_tools"]),
                    recommended_next_steps=json.loads(r["recommended_next_steps"]),
                    caveats=json.loads(r["caveats"]),
                )
            )
        return out


def _parse_dt(value: str) -> Any:
    from datetime import datetime
    return datetime.fromisoformat(value)


def _row_to_session(row: sqlite3.Row) -> Session:
    target = Target.model_validate_json(row["target_json"])
    finished = _parse_dt(row["finished_at"]) if row["finished_at"] else None
    return Session(
        id=row["id"],
        target=target,
        profile=row["profile"],
        started_at=_parse_dt(row["started_at"]),
        finished_at=finished,
        status=SessionStatus(row["status"]),
        tools_planned=json.loads(row["tools_planned"]),
        tools_ran=json.loads(row["tools_ran"]),
        tools_skipped=json.loads(row["tools_skipped"]),
        warnings=json.loads(row["warnings"]),
        ai_enabled=bool(row["ai_enabled"]),
        ai_model=row["ai_model"],
        ai_summary=row["ai_summary"],
        report_path=row["report_path"],
    )
