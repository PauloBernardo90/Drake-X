"""Append-only SQLite ledger for integrity events.

Provides a tamper-evident storage for custody events and integrity
reports using SQLite in WAL (Write-Ahead Logging) mode. Key properties:

- **Append-only**: no UPDATE or DELETE statements are issued
- **WAL mode**: concurrent readers never block, writes are durable
- **Linked hashing**: each ledger entry includes the hash of the
  previous entry, creating a simple chain
- **Per-run isolation**: each analysis run has its own sequence

Usage::

    ledger = IntegrityLedger(Path("workspace/integrity_ledger.db"))
    ledger.append_custody_event(event)
    ledger.append_integrity_report(report)
    entries = ledger.read_run("run-abc123")
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TYPE_CHECKING

from ..logging import get_logger
from .exceptions import IntegrityError
from .models import CustodyEvent, IntegrityReport

if TYPE_CHECKING:
    from ..core.workspace import Workspace

log = get_logger("integrity.ledger")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_entries (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '',
    link_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ledger_run_id ON ledger_entries(run_id);
CREATE INDEX IF NOT EXISTS idx_ledger_entry_type ON ledger_entries(entry_type);
CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON ledger_entries(timestamp);
"""


@dataclass(frozen=True)
class LedgerEntry:
    """One entry in the integrity ledger."""
    seq: int
    run_id: str
    entry_type: str           # "custody_event" | "integrity_report" | "verification"
    timestamp: str
    payload: dict[str, Any]
    payload_sha256: str
    prev_hash: str
    link_hash: str


class IntegrityLedger:
    """Append-only WAL-backed SQLite ledger for integrity events.

    Can operate in two modes:
    - Dedicated DB (default): creates its own ``integrity_ledger.db``
    - Shared DB: attaches its tables to an existing database (e.g. the
      workspace ``drake.db``). Tables are additive and namespaced so
      they coexist with Drake-X core tables.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @classmethod
    def for_workspace(cls, workspace: "Workspace") -> "IntegrityLedger":
        """Create a ledger that shares the workspace's drake.db.

        The ledger tables are additive — they coexist with sessions,
        findings, and evidence_graphs in the same database file.
        """
        return cls(workspace.db_path)

    def _init_db(self) -> None:
        """Initialize schema and enable WAL mode."""
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), isolation_level=None, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _last_link_hash(self, conn: sqlite3.Connection) -> str:
        """Get the link_hash of the most recent entry (for chaining)."""
        row = conn.execute(
            "SELECT link_hash FROM ledger_entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row["link_hash"] if row else ""

    def append_custody_event(self, event: CustodyEvent) -> LedgerEntry:
        """Append a custody event to the ledger."""
        return self._append(
            run_id=event.run_id,
            entry_type="custody_event",
            timestamp=event.timestamp,
            payload=event.model_dump(mode="json"),
        )

    def append_integrity_report(self, report: IntegrityReport) -> LedgerEntry:
        """Append an integrity report to the ledger."""
        return self._append(
            run_id=report.run_id,
            entry_type="integrity_report",
            timestamp=report.generated_at,
            payload=report.model_dump(mode="json"),
        )

    def append_verification(
        self,
        run_id: str,
        verified: bool,
        timestamp: str,
        details: dict[str, Any] | None = None,
    ) -> LedgerEntry:
        """Append a verification result to the ledger."""
        return self._append(
            run_id=run_id,
            entry_type="verification",
            timestamp=timestamp,
            payload={
                "verified": verified,
                "details": details or {},
            },
        )

    def _append(
        self,
        *,
        run_id: str,
        entry_type: str,
        timestamp: str,
        payload: dict[str, Any],
    ) -> LedgerEntry:
        """Append a generic entry with linked hashing."""
        if not run_id:
            raise IntegrityError("Cannot append ledger entry without run_id")

        payload_json = json.dumps(payload, sort_keys=True, default=str)
        payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

        with self._connect() as conn:
            prev_hash = self._last_link_hash(conn)
            # link_hash = SHA-256(prev_hash + payload_sha256 + run_id + entry_type)
            link_input = f"{prev_hash}|{payload_sha256}|{run_id}|{entry_type}"
            link_hash = hashlib.sha256(link_input.encode("utf-8")).hexdigest()

            cursor = conn.execute(
                """INSERT INTO ledger_entries
                   (run_id, entry_type, timestamp, payload, payload_sha256, prev_hash, link_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (run_id, entry_type, timestamp, payload_json,
                 payload_sha256, prev_hash, link_hash),
            )
            conn.commit()
            seq = cursor.lastrowid

        entry = LedgerEntry(
            seq=seq or 0,
            run_id=run_id,
            entry_type=entry_type,
            timestamp=timestamp,
            payload=payload,
            payload_sha256=payload_sha256,
            prev_hash=prev_hash,
            link_hash=link_hash,
        )

        log.info(
            "Ledger: appended seq=%d type=%s run=%s",
            entry.seq, entry_type, run_id,
        )
        return entry

    def read_run(self, run_id: str) -> list[LedgerEntry]:
        """Read all entries for a given run_id in sequence order."""
        entries: list[LedgerEntry] = []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM ledger_entries WHERE run_id = ? ORDER BY seq ASC",
                (run_id,),
            ).fetchall()

        for row in rows:
            entries.append(LedgerEntry(
                seq=row["seq"],
                run_id=row["run_id"],
                entry_type=row["entry_type"],
                timestamp=row["timestamp"],
                payload=json.loads(row["payload"]),
                payload_sha256=row["payload_sha256"],
                prev_hash=row["prev_hash"],
                link_hash=row["link_hash"],
            ))
        return entries

    def verify_chain(self, run_id: str | None = None) -> list[str]:
        """Verify the integrity of the linked-hash chain.

        If ``run_id`` is provided, verify only that run. Otherwise, verify
        the entire ledger.

        Returns a list of violation descriptions. Empty = valid.
        """
        violations: list[str] = []
        with self._connect() as conn:
            if run_id:
                rows = conn.execute(
                    "SELECT * FROM ledger_entries WHERE run_id = ? ORDER BY seq ASC",
                    (run_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM ledger_entries ORDER BY seq ASC"
                ).fetchall()

        expected_prev = "" if run_id else ""
        for row in rows:
            # Verify payload hash
            actual_payload_hash = hashlib.sha256(
                row["payload"].encode("utf-8")
            ).hexdigest()
            if actual_payload_hash != row["payload_sha256"]:
                violations.append(
                    f"seq={row['seq']}: payload hash mismatch"
                )

            # Verify link hash
            link_input = (
                f"{row['prev_hash']}|{row['payload_sha256']}|"
                f"{row['run_id']}|{row['entry_type']}"
            )
            expected_link = hashlib.sha256(link_input.encode("utf-8")).hexdigest()
            if expected_link != row["link_hash"]:
                violations.append(
                    f"seq={row['seq']}: link hash mismatch"
                )

            # Verify prev_hash chain (global only — per-run is not chained)
            if not run_id:
                if row["prev_hash"] != expected_prev:
                    violations.append(
                        f"seq={row['seq']}: prev_hash mismatch, "
                        f"expected {expected_prev[:16]}…, got {row['prev_hash'][:16]}…"
                    )
                expected_prev = row["link_hash"]

        return violations

    def count_entries(self) -> int:
        """Return total number of entries in the ledger."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM ledger_entries").fetchone()
            return row["n"] if row else 0

    def list_runs(self) -> list[str]:
        """Return all distinct run_ids in the ledger."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT run_id FROM ledger_entries ORDER BY run_id"
            ).fetchall()
        return [r["run_id"] for r in rows]

    def get_integrity_report(self, run_id: str) -> IntegrityReport | None:
        """Retrieve the most recent integrity_report entry for a run.

        Returns a reconstructed :class:`IntegrityReport` or None if no
        report entry exists for that run_id.
        """
        with self._connect() as conn:
            row = conn.execute(
                """SELECT payload FROM ledger_entries
                   WHERE run_id = ? AND entry_type = 'integrity_report'
                   ORDER BY seq DESC LIMIT 1""",
                (run_id,),
            ).fetchone()
        if not row:
            return None
        payload = json.loads(row["payload"])
        return IntegrityReport(**payload)

    def run_summary(self, run_id: str) -> dict[str, Any]:
        """Return a short summary of a run: entry counts, timestamps, verification."""
        entries = self.read_run(run_id)
        if not entries:
            return {"run_id": run_id, "found": False}

        by_type: dict[str, int] = {}
        for e in entries:
            by_type[e.entry_type] = by_type.get(e.entry_type, 0) + 1

        verified = None
        verify_entries = [e for e in entries if e.entry_type == "verification"]
        if verify_entries:
            verified = verify_entries[-1].payload.get("verified")

        return {
            "run_id": run_id,
            "found": True,
            "entry_count": len(entries),
            "entry_types": by_type,
            "first_timestamp": entries[0].timestamp,
            "last_timestamp": entries[-1].timestamp,
            "verified": verified,
        }
