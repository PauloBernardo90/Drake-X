"""Workspace-rooted storage layer.

:class:`WorkspaceStorage` is the v2 storage facade. It composes the v1
:class:`drake_x.session_store.SessionStore` (which already handles sessions,
tool results, artifacts and basic findings) and adds the new tables Drake-X
v0.2 needs:

- ``scope_assets``  — snapshot of in/out-of-scope rules per session
- ``audit_meta``    — bookkeeping for the audit log (last-rotation marker)
- ``finding_extras`` — additive columns for the extended Finding model
                     (cwe, owasp, mitre, evidence, fact_or_inference, …)

The schema is created additively so existing v1 databases work without
losing data.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from ..exceptions import StorageError
from ..models.finding import Finding, FindingEvidence, FindingSeverity, FindingSource
from ..models.scope import ScopeAsset, ScopeFile
from ..session_store import SessionStore

_V2_SCHEMA = """
CREATE TABLE IF NOT EXISTS scope_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    direction TEXT NOT NULL,            -- 'in' or 'out'
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    notes TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS finding_extras (
    finding_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    fact_or_inference TEXT NOT NULL DEFAULT 'fact',
    cwe TEXT NOT NULL DEFAULT '[]',
    owasp TEXT NOT NULL DEFAULT '[]',
    mitre_attck TEXT NOT NULL DEFAULT '[]',
    related_tools TEXT NOT NULL DEFAULT '[]',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    recommended_next_steps TEXT NOT NULL DEFAULT '[]',
    remediation TEXT,
    caveats TEXT NOT NULL DEFAULT '[]',
    tags TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS finding_extras_session_idx
    ON finding_extras(session_id);

CREATE TABLE IF NOT EXISTS assist_sessions (
    id TEXT PRIMARY KEY,
    workspace TEXT NOT NULL,
    domain TEXT NOT NULL,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT
);

CREATE TABLE IF NOT EXISTS assist_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assist_session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    step_number INTEGER NOT NULL,
    suggestion_json TEXT NOT NULL,
    operator_action TEXT NOT NULL,
    executed_command TEXT,
    result_status TEXT,
    FOREIGN KEY (assist_session_id) REFERENCES assist_sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence_graphs (
    session_id TEXT PRIMARY KEY,
    graph_json TEXT NOT NULL,
    node_count INTEGER NOT NULL DEFAULT 0,
    edge_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

-- v1.0 additions

CREATE TABLE IF NOT EXISTS validation_plans (
    session_id TEXT PRIMARY KEY,
    plan_json TEXT NOT NULL,
    item_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
"""


class WorkspaceStorage:
    """Composes :class:`SessionStore` (v1) with the v2 tables."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # SessionStore initializes the v1 schema for us.
        self.legacy = SessionStore(self.db_path)
        self._init_v2_schema()

    # ----- session/result/artifact passthroughs ------------------------

    @property
    def sessions(self) -> SessionStore:
        """Direct handle to the v1 store for callers that already use it."""
        return self.legacy

    # ----- v2: scope snapshot ------------------------------------------

    def save_scope_snapshot(self, session_id: str, scope: ScopeFile) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "DELETE FROM scope_assets WHERE session_id = ?", (session_id,)
                )
                rows = []
                for asset in scope.in_scope:
                    rows.append((session_id, "in", asset.kind, asset.value, asset.notes))
                for asset in scope.out_of_scope:
                    rows.append((session_id, "out", asset.kind, asset.value, asset.notes))
                if rows:
                    conn.executemany(
                        "INSERT INTO scope_assets (session_id, direction, kind, value, notes) "
                        "VALUES (?, ?, ?, ?, ?)",
                        rows,
                    )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to persist scope snapshot: {exc}") from exc

    def load_scope_snapshot(self, session_id: str) -> tuple[list[ScopeAsset], list[ScopeAsset]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT direction, kind, value, notes FROM scope_assets WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            ).fetchall()
        in_scope: list[ScopeAsset] = []
        out_of_scope: list[ScopeAsset] = []
        for r in rows:
            asset = ScopeAsset(kind=r["kind"], value=r["value"], notes=r["notes"])
            if r["direction"] == "in":
                in_scope.append(asset)
            else:
                out_of_scope.append(asset)
        return in_scope, out_of_scope

    # ----- v2: extended findings ---------------------------------------

    def save_finding(self, session_id: str, finding: Finding) -> None:
        # Always write to the v1 table so v1 tooling continues to see findings.
        self.legacy.save_finding(session_id, finding)
        # Then write the v2 extras keyed by finding.id.
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO finding_extras (
                        finding_id, session_id, title, summary, severity, confidence, source,
                        fact_or_inference, cwe, owasp, mitre_attck, related_tools,
                        evidence_json, recommended_next_steps, remediation, caveats, tags
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(finding_id) DO UPDATE SET
                        title=excluded.title,
                        summary=excluded.summary,
                        severity=excluded.severity,
                        confidence=excluded.confidence,
                        source=excluded.source,
                        fact_or_inference=excluded.fact_or_inference,
                        cwe=excluded.cwe,
                        owasp=excluded.owasp,
                        mitre_attck=excluded.mitre_attck,
                        related_tools=excluded.related_tools,
                        evidence_json=excluded.evidence_json,
                        recommended_next_steps=excluded.recommended_next_steps,
                        remediation=excluded.remediation,
                        caveats=excluded.caveats,
                        tags=excluded.tags
                    """,
                    (
                        finding.id,
                        session_id,
                        finding.title,
                        finding.summary,
                        finding.severity.value,
                        finding.confidence,
                        finding.source.value,
                        finding.fact_or_inference,
                        json.dumps(finding.cwe),
                        json.dumps(finding.owasp),
                        json.dumps(finding.mitre_attck),
                        json.dumps(finding.related_tools),
                        json.dumps([e.model_dump() for e in finding.evidence]),
                        json.dumps(finding.recommended_next_steps),
                        finding.remediation,
                        json.dumps(finding.caveats),
                        json.dumps(finding.tags),
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to persist finding extras for {finding.id}: {exc}"
            ) from exc

    def update_finding_tags(self, finding_id: str, tags: list[str]) -> bool:
        """Replace the ``tags`` column on a v2 finding row in place.

        Returns ``True`` when the row existed and was updated, ``False``
        when there was no v2 row to update (legacy v1-only findings).

        This is the supported way to mutate finding metadata after
        creation: it touches only the v2 ``finding_extras`` table, so it
        does not append a duplicate row to the legacy ``findings`` table
        the way :meth:`save_finding` would.
        """
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "UPDATE finding_extras SET tags = ? WHERE finding_id = ?",
                    (json.dumps(tags), finding_id),
                )
                return cursor.rowcount > 0
        except sqlite3.Error as exc:
            raise StorageError(
                f"failed to update tags for finding {finding_id}: {exc}"
            ) from exc

    def load_findings(self, session_id: str) -> list[Finding]:
        """Load extended findings, preferring v2 rows when present."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM finding_extras WHERE session_id = ? ORDER BY rowid ASC",
                (session_id,),
            ).fetchall()
        findings: list[Finding] = []
        for r in rows:
            evidence = [
                FindingEvidence(**e) for e in json.loads(r["evidence_json"] or "[]")
            ]
            findings.append(
                Finding(
                    id=r["finding_id"],
                    title=r["title"],
                    summary=r["summary"],
                    severity=FindingSeverity(r["severity"]),
                    confidence=r["confidence"],
                    source=FindingSource(r["source"]),
                    fact_or_inference=r["fact_or_inference"],
                    cwe=json.loads(r["cwe"] or "[]"),
                    owasp=json.loads(r["owasp"] or "[]"),
                    mitre_attck=json.loads(r["mitre_attck"] or "[]"),
                    related_tools=json.loads(r["related_tools"] or "[]"),
                    evidence=evidence,
                    recommended_next_steps=json.loads(r["recommended_next_steps"] or "[]"),
                    remediation=r["remediation"],
                    caveats=json.loads(r["caveats"] or "[]"),
                    tags=json.loads(r["tags"] or "[]"),
                )
            )
        if findings:
            return findings
        # Fall back to the v1 store for legacy databases.
        return self.legacy.load_findings(session_id)

    # ----- v2: assist sessions -------------------------------------------

    def create_assist_session(
        self, assist_id: str, workspace: str, domain: str, target: str, started_at: str,
    ) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO assist_sessions (id, workspace, domain, target, started_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (assist_id, workspace, domain, target, started_at),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to create assist session: {exc}") from exc

    def end_assist_session(self, assist_id: str, ended_at: str) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE assist_sessions SET ended_at = ? WHERE id = ?",
                    (ended_at, assist_id),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to end assist session: {exc}") from exc

    def log_assist_event(
        self,
        assist_session_id: str,
        timestamp: str,
        step_number: int,
        suggestion_json: str,
        operator_action: str,
        executed_command: str | None = None,
        result_status: str | None = None,
    ) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO assist_events "
                    "(assist_session_id, timestamp, step_number, suggestion_json, "
                    "operator_action, executed_command, result_status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (assist_session_id, timestamp, step_number, suggestion_json,
                     operator_action, executed_command, result_status),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to log assist event: {exc}") from exc

    def load_assist_events(self, assist_session_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM assist_events WHERE assist_session_id = ? ORDER BY step_number ASC",
                (assist_session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def list_assist_sessions(self, limit: int = 20) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM assist_sessions ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ----- v2: evidence graph -------------------------------------------

    def save_evidence_graph(self, session_id: str, graph: "EvidenceGraph") -> None:
        """Persist an evidence graph for a session."""
        from ..models.evidence_graph import EvidenceGraph  # deferred to avoid circular

        graph_json = graph.to_json()
        stats = graph.stats()
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO evidence_graphs (session_id, graph_json, node_count, edge_count)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        graph_json=excluded.graph_json,
                        node_count=excluded.node_count,
                        edge_count=excluded.edge_count
                    """,
                    (session_id, graph_json, stats["total_nodes"], stats["total_edges"]),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to persist evidence graph: {exc}") from exc

    def load_evidence_graph(self, session_id: str) -> "EvidenceGraph | None":
        """Load an evidence graph for a session, or ``None``."""
        from ..models.evidence_graph import EvidenceGraph

        with self._connect() as conn:
            row = conn.execute(
                "SELECT graph_json FROM evidence_graphs WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            data = json.loads(row["graph_json"])
            return EvidenceGraph.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            return None

    # ----- v1.0: validation plans --------------------------------------

    def save_validation_plan(self, session_id: str, plan: "object") -> None:
        """Persist a :class:`ValidationPlan` for a session."""
        plan_json = plan.model_dump_json()
        item_count = len(getattr(plan, "items", []))
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO validation_plans (session_id, plan_json, item_count)
                    VALUES (?, ?, ?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        plan_json=excluded.plan_json,
                        item_count=excluded.item_count
                    """,
                    (session_id, plan_json, item_count),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to persist validation plan: {exc}") from exc

    def load_validation_plan(self, session_id: str):
        """Load a :class:`ValidationPlan` for a session, or ``None``."""
        from ..models.validation_plan import ValidationPlan

        with self._connect() as conn:
            row = conn.execute(
                "SELECT plan_json FROM validation_plans WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            return ValidationPlan.model_validate_json(row["plan_json"])
        except Exception:
            return None

    # ----- v1.0: jobs (experimental execution foundation) --------------

    def enqueue_job(self, job) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO jobs (
                        id, kind, payload_json, status, attempts, max_attempts,
                        error, created_at, started_at, finished_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job.id, job.kind, json.dumps(job.payload, default=str),
                        job.status, job.attempts, job.max_attempts,
                        job.error, job.created_at, job.started_at, job.finished_at,
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to enqueue job: {exc}") from exc

    def update_job(self, job) -> None:
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE jobs SET
                        status=?, attempts=?, error=?,
                        started_at=?, finished_at=?
                    WHERE id=?
                    """,
                    (
                        job.status, job.attempts, job.error,
                        job.started_at, job.finished_at, job.id,
                    ),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to update job: {exc}") from exc

    def load_jobs(self, *, status: str | None = None, limit: int = 100) -> list[dict]:
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM jobs WHERE status = ? ORDER BY created_at ASC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM jobs ORDER BY created_at ASC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    # ----- internals ---------------------------------------------------

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

    def _init_v2_schema(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(_V2_SCHEMA)
        except sqlite3.Error as exc:
            raise StorageError(f"failed to initialize v2 schema: {exc}") from exc
