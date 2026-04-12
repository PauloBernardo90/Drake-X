"""Tests for the AI audit log (v0.9)."""

from __future__ import annotations

import hashlib
import json

from drake_x.ai.audit import build_record, read_records, write_record


def test_build_record_hashes_prompt(tmp_path):
    rec = build_record(
        task="exploit_assessment",
        model="llama3.1:8b",
        prompt="hello prompt",
        context_node_ids=["a", "b"],
        raw_response="{}",
        parsed={},
    )
    expected = hashlib.sha256(b"hello prompt").hexdigest()
    assert rec.prompt_sha256 == expected
    assert rec.prompt_chars == len("hello prompt")


def test_context_ids_sorted_and_deduped(tmp_path):
    rec = build_record(
        task="exploit_assessment",
        model="m",
        prompt="p",
        context_node_ids=["b", "a", "b", "c"],
        raw_response="",
        parsed=None,
    )
    assert rec.context_node_ids == ["a", "b", "c"]


def test_write_and_read_roundtrip(tmp_path):
    rec = build_record(
        task="exploit_assessment",
        model="m",
        prompt="p",
        context_node_ids=["x"],
        raw_response='{"ok": true}',
        parsed={"ok": True},
        truncation_notes=["graph truncated"],
    )
    path = write_record(rec, tmp_path)
    assert path.exists()
    recs = read_records(tmp_path, "exploit_assessment")
    assert len(recs) == 1
    assert recs[0].prompt_sha256 == rec.prompt_sha256
    assert recs[0].parsed == {"ok": True}
    assert recs[0].truncation_notes == ["graph truncated"]


def test_failed_tasks_still_recorded(tmp_path):
    rec = build_record(
        task="exploit_assessment",
        model="m",
        prompt="p",
        context_node_ids=[],
        raw_response="not json",
        parsed=None,
        ok=False,
        error="model response was not valid JSON",
    )
    write_record(rec, tmp_path)
    recs = read_records(tmp_path, "exploit_assessment")
    assert len(recs) == 1
    assert recs[0].ok is False
    assert "JSON" in (recs[0].error or "")


def test_malformed_line_is_skipped_not_raised(tmp_path):
    path = tmp_path / "exploit_assessment.jsonl"
    path.write_text(
        '{"task": "exploit_assessment", "model": "m", "timestamp": "t", '
        '"prompt_sha256": "x"}\n'
        "NOT JSON\n",
        encoding="utf-8",
    )
    recs = read_records(tmp_path, "exploit_assessment")
    assert len(recs) == 1  # malformed second line skipped


def test_append_only(tmp_path):
    for i in range(3):
        rec = build_record(
            task="exploit_assessment",
            model="m",
            prompt=f"p{i}",
            context_node_ids=[],
            raw_response="",
            parsed=None,
        )
        write_record(rec, tmp_path)
    recs = read_records(tmp_path, "exploit_assessment")
    assert len(recs) == 3
    # Distinct prompt hashes confirm no overwrite.
    assert len({r.prompt_sha256 for r in recs}) == 3
