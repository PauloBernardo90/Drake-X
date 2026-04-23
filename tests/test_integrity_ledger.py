"""Tests for drake_x.integrity.ledger — append-only WAL SQLite ledger."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from drake_x.integrity.exceptions import IntegrityError
from drake_x.integrity.ledger import IntegrityLedger, LedgerEntry
from drake_x.integrity.models import (
    CustodyAction,
    CustodyEvent,
    CustodyStatus,
    IntegrityReport,
)


@pytest.fixture
def ledger(tmp_path: Path) -> IntegrityLedger:
    return IntegrityLedger(tmp_path / "ledger.db")


@pytest.fixture
def sample_event() -> CustodyEvent:
    return CustodyEvent(
        run_id="run-test123",
        action=CustodyAction.INGEST,
        artifact_sha256="a" * 64,
        actor="test",
        details="Ingested sample",
        status=CustodyStatus.OK,
    )


@pytest.fixture
def sample_report() -> IntegrityReport:
    return IntegrityReport(
        run_id="run-test123",
        sample_sha256="a" * 64,
        sample_identity={"sha256": "a" * 64},
        report_sha256="b" * 64,
    )


class TestLedgerInitialization:
    def test_creates_db_file(self, tmp_path: Path) -> None:
        db = tmp_path / "new.db"
        assert not db.exists()
        IntegrityLedger(db)
        assert db.exists()

    def test_wal_mode_enabled(self, ledger: IntegrityLedger, tmp_path: Path) -> None:
        conn = sqlite3.connect(str(tmp_path / "ledger.db"))
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        assert mode == "wal"

    def test_schema_created(self, ledger: IntegrityLedger, tmp_path: Path) -> None:
        conn = sqlite3.connect(str(tmp_path / "ledger.db"))
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )]
        conn.close()
        assert "ledger_entries" in tables

    def test_parent_dir_created(self, tmp_path: Path) -> None:
        db = tmp_path / "sub" / "dir" / "ledger.db"
        IntegrityLedger(db)
        assert db.exists()


class TestAppendCustodyEvent:
    def test_append_event(self, ledger: IntegrityLedger, sample_event: CustodyEvent) -> None:
        entry = ledger.append_custody_event(sample_event)
        assert entry.seq >= 1
        assert entry.run_id == "run-test123"
        assert entry.entry_type == "custody_event"
        assert len(entry.link_hash) == 64

    def test_payload_hash_correct(self, ledger: IntegrityLedger, sample_event: CustodyEvent) -> None:
        entry = ledger.append_custody_event(sample_event)
        assert len(entry.payload_sha256) == 64

    def test_first_entry_empty_prev_hash(self, ledger: IntegrityLedger, sample_event: CustodyEvent) -> None:
        entry = ledger.append_custody_event(sample_event)
        assert entry.prev_hash == ""

    def test_chained_entries(self, ledger: IntegrityLedger, sample_event: CustodyEvent) -> None:
        e1 = ledger.append_custody_event(sample_event)
        e2 = ledger.append_custody_event(sample_event)
        assert e2.prev_hash == e1.link_hash
        assert e2.seq == e1.seq + 1

    def test_empty_run_id_raises(self, ledger: IntegrityLedger) -> None:
        bad_event = CustodyEvent(run_id="", action=CustodyAction.INGEST)
        with pytest.raises(IntegrityError):
            ledger.append_custody_event(bad_event)


class TestAppendIntegrityReport:
    def test_append_report(self, ledger: IntegrityLedger, sample_report: IntegrityReport) -> None:
        entry = ledger.append_integrity_report(sample_report)
        assert entry.entry_type == "integrity_report"
        assert entry.run_id == "run-test123"


class TestAppendVerification:
    def test_append_verification(self, ledger: IntegrityLedger) -> None:
        entry = ledger.append_verification(
            run_id="run-abc",
            verified=True,
            timestamp="2025-01-15T10:00:00+00:00",
            details={"errors": []},
        )
        assert entry.entry_type == "verification"
        assert entry.payload["verified"] is True


class TestReadRun:
    def test_read_empty_run(self, ledger: IntegrityLedger) -> None:
        assert ledger.read_run("nonexistent") == []

    def test_read_single_run(self, ledger: IntegrityLedger, sample_event: CustodyEvent) -> None:
        ledger.append_custody_event(sample_event)
        entries = ledger.read_run("run-test123")
        assert len(entries) == 1
        assert entries[0].run_id == "run-test123"

    def test_read_preserves_order(self, ledger: IntegrityLedger) -> None:
        for i in range(5):
            ledger.append_custody_event(CustodyEvent(
                run_id="run-abc",
                action=CustodyAction.ANALYZE,
                details=f"step-{i}",
            ))
        entries = ledger.read_run("run-abc")
        assert len(entries) == 5
        for i, e in enumerate(entries):
            assert e.payload["details"] == f"step-{i}"

    def test_multiple_runs_isolated(self, ledger: IntegrityLedger) -> None:
        ledger.append_custody_event(CustodyEvent(
            run_id="run-A", action=CustodyAction.INGEST,
        ))
        ledger.append_custody_event(CustodyEvent(
            run_id="run-B", action=CustodyAction.INGEST,
        ))
        assert len(ledger.read_run("run-A")) == 1
        assert len(ledger.read_run("run-B")) == 1


class TestVerifyChain:
    def test_empty_ledger_valid(self, ledger: IntegrityLedger) -> None:
        assert ledger.verify_chain() == []

    def test_valid_chain_passes(self, ledger: IntegrityLedger, sample_event: CustodyEvent) -> None:
        ledger.append_custody_event(sample_event)
        ledger.append_custody_event(sample_event)
        ledger.append_custody_event(sample_event)
        violations = ledger.verify_chain()
        assert violations == []

    def test_tampered_payload_detected(
        self,
        ledger: IntegrityLedger,
        sample_event: CustodyEvent,
        tmp_path: Path,
    ) -> None:
        ledger.append_custody_event(sample_event)
        # Tamper with the payload directly
        conn = sqlite3.connect(str(tmp_path / "ledger.db"))
        conn.execute(
            "UPDATE ledger_entries SET payload = ? WHERE seq = 1",
            ('{"tampered": true}',),
        )
        conn.commit()
        conn.close()

        violations = ledger.verify_chain()
        assert len(violations) >= 1
        assert any("hash mismatch" in v.lower() for v in violations)


class TestLedgerStats:
    def test_count_entries(self, ledger: IntegrityLedger, sample_event: CustodyEvent) -> None:
        assert ledger.count_entries() == 0
        ledger.append_custody_event(sample_event)
        ledger.append_custody_event(sample_event)
        assert ledger.count_entries() == 2

    def test_list_runs(self, ledger: IntegrityLedger) -> None:
        assert ledger.list_runs() == []
        ledger.append_custody_event(CustodyEvent(run_id="run-A", action=CustodyAction.INGEST))
        ledger.append_custody_event(CustodyEvent(run_id="run-B", action=CustodyAction.INGEST))
        ledger.append_custody_event(CustodyEvent(run_id="run-A", action=CustodyAction.ANALYZE))
        runs = ledger.list_runs()
        assert set(runs) == {"run-A", "run-B"}
