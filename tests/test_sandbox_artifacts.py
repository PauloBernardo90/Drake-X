"""Tests for drake_x.sandbox.artifact_collector — output artifact collection."""

from __future__ import annotations

from pathlib import Path

import pytest

from drake_x.sandbox.artifact_collector import (
    ArtifactCollection,
    CollectedArtifact,
    collect_artifacts,
    copy_artifacts,
)


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    d = tmp_path / "output"
    d.mkdir()
    (d / "logcat.txt").write_text("I/ActivityManager: Start proc\n" * 100)
    (d / "strings.txt").write_text("http://evil.com\nsome_string\n")
    (d / "decoded.json").write_text('{"key": "value"}')
    sub = d / "subdir"
    sub.mkdir()
    (sub / "nested.bin").write_bytes(b"\x00" * 50)
    return d


class TestCollectArtifacts:
    def test_collects_all_files(self, output_dir: Path) -> None:
        collection = collect_artifacts(output_dir, run_id="test-run")
        assert collection.run_id == "test-run"
        assert len(collection.artifacts) == 4
        assert collection.total_size > 0

    def test_artifact_metadata(self, output_dir: Path) -> None:
        collection = collect_artifacts(output_dir)
        names = {a.filename for a in collection.artifacts}
        assert "logcat.txt" in names
        assert "strings.txt" in names

        logcat = next(a for a in collection.artifacts if a.filename == "logcat.txt")
        assert logcat.artifact_type == "text"
        assert logcat.size > 0
        assert len(logcat.sha256) == 64

    def test_json_type_inferred(self, output_dir: Path) -> None:
        collection = collect_artifacts(output_dir)
        json_art = next(a for a in collection.artifacts if a.filename == "decoded.json")
        assert json_art.artifact_type == "json"

    def test_nested_files(self, output_dir: Path) -> None:
        collection = collect_artifacts(output_dir)
        nested = next(a for a in collection.artifacts if a.filename == "nested.bin")
        assert nested.artifact_type == "binary"
        assert "subdir" in nested.path

    def test_empty_directory(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        collection = collect_artifacts(empty)
        assert len(collection.artifacts) == 0

    def test_nonexistent_directory(self, tmp_path: Path) -> None:
        collection = collect_artifacts(tmp_path / "nope")
        assert len(collection.artifacts) == 0
        assert len(collection.collection_notes) >= 1

    def test_max_artifacts_cap(self, output_dir: Path) -> None:
        collection = collect_artifacts(output_dir, max_artifacts=2)
        assert len(collection.artifacts) == 2
        assert any("cap reached" in n for n in collection.collection_notes)

    def test_to_dict(self, output_dir: Path) -> None:
        collection = collect_artifacts(output_dir, run_id="test")
        d = collection.to_dict()
        assert d["run_id"] == "test"
        assert d["artifact_count"] == 4
        assert len(d["artifacts"]) == 4
        assert all("sha256" in a for a in d["artifacts"])


class TestCopyArtifacts:
    def test_copies_files(self, output_dir: Path, tmp_path: Path) -> None:
        collection = collect_artifacts(output_dir)
        dest = tmp_path / "copied"
        copied = copy_artifacts(collection, output_dir, dest)
        assert len(copied) >= 3
        assert dest.exists()
        assert (dest / "logcat.txt").exists()

    def test_creates_dest_dir(self, output_dir: Path, tmp_path: Path) -> None:
        collection = collect_artifacts(output_dir)
        dest = tmp_path / "new" / "nested" / "dest"
        copy_artifacts(collection, output_dir, dest)
        assert dest.exists()
