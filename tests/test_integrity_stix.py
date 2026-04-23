"""Tests for drake_x.integrity.stix_bundle — STIX 2.1 provenance bundle."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drake_x.integrity.models import (
    AnalysisVersionInfo,
    ArtifactRecord,
    CustodyAction,
    CustodyEvent,
    CustodyStatus,
    ExecutionContext,
    IntegrityReport,
)
from drake_x.integrity.stix_bundle import render_provenance_stix


@pytest.fixture
def sample_report() -> IntegrityReport:
    sha = "deadbeef" * 8
    return IntegrityReport(
        run_id="run-test123",
        sample_sha256=sha,
        sample_identity={
            "file_name": "sample.apk",
            "file_size": 12345,
            "md5": "m" * 32,
            "sha1": "s" * 40,
            "sha256": sha,
        },
        execution_context=ExecutionContext(
            run_id="run-test123",
            sample_sha256=sha,
            analysis_mode="apk_analyze",
        ),
        version_info=AnalysisVersionInfo(
            drake_x_version="1.0.0",
            pipeline_version="1.0.0",
            analysis_profile="apk_analyze",
        ),
        artifacts=[
            ArtifactRecord(
                artifact_type="apk_original",
                file_name="sample.apk",
                sha256=sha,
                parent_sha256=sha,
                run_id="run-test123",
                file_size=12345,
            ),
            ArtifactRecord(
                artifact_type="report_json",
                file_name="apk_analysis.json",
                sha256="e" * 64,
                parent_sha256=sha,
                run_id="run-test123",
            ),
        ],
        custody_events=[
            CustodyEvent(
                run_id="run-test123",
                action=CustodyAction.INGEST,
                artifact_sha256=sha,
                actor="apk_cmd",
                details="Ingested sample.apk",
            ),
            CustodyEvent(
                run_id="run-test123",
                action=CustodyAction.ANALYZE,
                actor="apk_analyze",
                details="Analysis completed",
            ),
        ],
        verified=True,
        report_sha256="r" * 64,
    )


class TestRenderProvenanceStix:
    def test_produces_valid_json(self, sample_report: IntegrityReport) -> None:
        stix = render_provenance_stix(sample_report)
        bundle = json.loads(stix)
        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert "objects" in bundle

    def test_bundle_has_identity(self, sample_report: IntegrityReport) -> None:
        stix = render_provenance_stix(sample_report)
        bundle = json.loads(stix)
        identities = [o for o in bundle["objects"] if o["type"] == "identity"]
        assert len(identities) == 1
        assert "Drake-X" in identities[0]["name"]

    def test_bundle_has_file_observable(self, sample_report: IntegrityReport) -> None:
        stix = render_provenance_stix(sample_report)
        bundle = json.loads(stix)
        files = [o for o in bundle["objects"] if o["type"] == "file"]
        assert len(files) == 1
        f = files[0]
        assert f["hashes"]["SHA-256"] == "deadbeef" * 8
        assert f["hashes"]["MD5"] == "m" * 32
        assert f["hashes"]["SHA-1"] == "s" * 40
        assert f["size"] == 12345
        assert f["name"] == "sample.apk"

    def test_bundle_has_process(self, sample_report: IntegrityReport) -> None:
        stix = render_provenance_stix(sample_report)
        bundle = json.loads(stix)
        processes = [o for o in bundle["objects"] if o["type"] == "process"]
        assert len(processes) == 1
        assert "apk_analyze" in processes[0]["command_line"]

    def test_bundle_has_custody_notes(self, sample_report: IntegrityReport) -> None:
        stix = render_provenance_stix(sample_report)
        bundle = json.loads(stix)
        notes = [o for o in bundle["objects"] if o["type"] == "note"]
        # 2 custody events + 2 artifacts = 4 notes
        assert len(notes) == 4
        custody_notes = [n for n in notes if "custody-event" in n.get("labels", [])]
        assert len(custody_notes) == 2

    def test_bundle_has_relationships(self, sample_report: IntegrityReport) -> None:
        stix = render_provenance_stix(sample_report)
        bundle = json.loads(stix)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) >= 1
        # At least one "analyzes" relationship
        analyzes = [r for r in rels if r["relationship_type"] == "analyzes"]
        assert len(analyzes) >= 1

    def test_drake_x_metadata(self, sample_report: IntegrityReport) -> None:
        stix = render_provenance_stix(sample_report)
        bundle = json.loads(stix)
        assert "x_drake_x" in bundle
        assert bundle["x_drake_x"]["run_id"] == "run-test123"
        assert bundle["x_drake_x"]["integrity_verified"] is True
        assert bundle["x_drake_x"]["analysis_type"] == "integrity_provenance"

    def test_deterministic(self, sample_report: IntegrityReport) -> None:
        """Same report produces identical STIX bundle."""
        s1 = render_provenance_stix(sample_report)
        s2 = render_provenance_stix(sample_report)
        assert s1 == s2

    def test_empty_without_sha256(self) -> None:
        report = IntegrityReport(run_id="run-x", sample_sha256="")
        assert render_provenance_stix(report) == ""

    def test_all_objects_have_stable_ids(self, sample_report: IntegrityReport) -> None:
        """All STIX objects should have stable UUIDs derived from content."""
        s1 = render_provenance_stix(sample_report)
        s2 = render_provenance_stix(sample_report)
        b1 = json.loads(s1)
        b2 = json.loads(s2)
        ids1 = [o["id"] for o in b1["objects"]]
        ids2 = [o["id"] for o in b2["objects"]]
        assert ids1 == ids2

    def test_timestamps_frozen(self, sample_report: IntegrityReport) -> None:
        stix = render_provenance_stix(sample_report)
        bundle = json.loads(stix)
        for obj in bundle["objects"]:
            if "created" in obj:
                assert obj["created"] == "1970-01-01T00:00:00+00:00"
