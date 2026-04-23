"""Tests for drake_x.integrity.chain — chain of custody tracker."""

from __future__ import annotations

from pathlib import Path

import pytest

from drake_x.integrity.chain import CustodyChain
from drake_x.integrity.exceptions import CustodyChainError, MissingRunIdError
from drake_x.integrity.models import CustodyAction, CustodyStatus


@pytest.fixture
def chain() -> CustodyChain:
    return CustodyChain(run_id="run-test123", sample_sha256="abcd1234" * 8)


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    f = tmp_path / "sample.apk"
    f.write_bytes(b"\x00" * 100)
    return f


class TestCustodyChainCreation:
    def test_creates_with_valid_params(self) -> None:
        chain = CustodyChain(run_id="run-abc", sample_sha256="dead" * 16)
        assert chain.run_id == "run-abc"
        assert chain.sample_sha256 == "dead" * 16

    def test_missing_run_id_raises(self) -> None:
        with pytest.raises(MissingRunIdError):
            CustodyChain(run_id="", sample_sha256="abc123")

    def test_missing_sha256_raises(self) -> None:
        with pytest.raises(CustodyChainError):
            CustodyChain(run_id="run-abc", sample_sha256="")


class TestCustodyEvents:
    def test_record_event(self, chain: CustodyChain) -> None:
        event = chain.record(
            CustodyAction.INGEST,
            actor="test",
            details="Ingested sample",
        )
        assert event.action == CustodyAction.INGEST
        assert event.run_id == "run-test123"
        assert event.actor == "test"
        assert event.status == CustodyStatus.OK

    def test_events_ordered(self, chain: CustodyChain) -> None:
        chain.record(CustodyAction.INGEST, actor="a")
        chain.record(CustodyAction.STAGE, actor="b")
        chain.record(CustodyAction.ANALYZE, actor="c")
        events = chain.events
        assert len(events) == 3
        assert events[0].action == CustodyAction.INGEST
        assert events[1].action == CustodyAction.STAGE
        assert events[2].action == CustodyAction.ANALYZE

    def test_events_immutable(self, chain: CustodyChain) -> None:
        chain.record(CustodyAction.INGEST, actor="a")
        events = chain.events
        assert len(events) == 1
        events.clear()  # Should not affect internal state
        assert len(chain.events) == 1

    def test_record_failure(self, chain: CustodyChain) -> None:
        event = chain.record_failure(actor="test", details="Something went wrong")
        assert event.action == CustodyAction.FAIL
        assert event.status == CustodyStatus.FAILED

    def test_default_artifact_sha256(self, chain: CustodyChain) -> None:
        event = chain.record(CustodyAction.INGEST, actor="test")
        assert event.artifact_sha256 == chain.sample_sha256

    def test_custom_artifact_sha256(self, chain: CustodyChain) -> None:
        event = chain.record(
            CustodyAction.ARTIFACT_REGISTER,
            artifact_sha256="custom_hash",
            actor="test",
        )
        assert event.artifact_sha256 == "custom_hash"


class TestArtifactRegistration:
    def test_register_artifact(self, chain: CustodyChain, sample_file: Path) -> None:
        record = chain.register_artifact(
            artifact_type="apk",
            file_path=sample_file,
        )
        assert record.artifact_type == "apk"
        assert record.file_name == "sample.apk"
        assert len(record.sha256) == 64
        assert record.parent_sha256 == chain.sample_sha256
        assert record.run_id == chain.run_id

    def test_register_creates_custody_event(self, chain: CustodyChain, sample_file: Path) -> None:
        chain.register_artifact(artifact_type="dex", file_path=sample_file)
        events = chain.events
        assert any(e.action == CustodyAction.ARTIFACT_REGISTER for e in events)

    def test_artifacts_list(self, chain: CustodyChain, sample_file: Path) -> None:
        chain.register_artifact(artifact_type="apk", file_path=sample_file)
        chain.register_artifact(artifact_type="dex", file_path=sample_file)
        assert len(chain.artifacts) == 2


class TestChainVerification:
    def test_valid_chain(self, chain: CustodyChain) -> None:
        chain.record(CustodyAction.INGEST, actor="test")
        violations = chain.verify_completeness()
        assert violations == []

    def test_missing_ingest_event(self, chain: CustodyChain) -> None:
        chain.record(CustodyAction.ANALYZE, actor="test")
        violations = chain.verify_completeness()
        assert any("ingest" in v.lower() for v in violations)

    def test_run_id_mismatch(self) -> None:
        chain = CustodyChain(run_id="run-abc", sample_sha256="dead" * 16)
        # Manually create event with wrong run_id (would be a bug)
        from drake_x.integrity.models import CustodyEvent
        bad_event = CustodyEvent(run_id="run-WRONG", action=CustodyAction.INGEST)
        chain._events.append(bad_event)
        violations = chain.verify_completeness()
        assert any("mismatch" in v.lower() for v in violations)


class TestChainSerialization:
    def test_to_dict(self, chain: CustodyChain, sample_file: Path) -> None:
        chain.record(CustodyAction.INGEST, actor="test")
        chain.register_artifact(artifact_type="apk", file_path=sample_file)
        d = chain.to_dict()
        assert d["run_id"] == "run-test123"
        assert d["event_count"] >= 1
        assert d["artifact_count"] == 1
        assert len(d["events"]) >= 1
        assert len(d["artifacts"]) == 1
