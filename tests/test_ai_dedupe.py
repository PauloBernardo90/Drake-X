"""Tests for the v0.3 dedupe AI task + CLI command + storage update."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from drake_x.ai.ollama_client import OllamaClient
from drake_x.ai.tasks import ALL_TASKS, DedupeTask
from drake_x.cli import app
from drake_x.core.storage import WorkspaceStorage
from drake_x.core.workspace import Workspace
from drake_x.models.finding import Finding, FindingSeverity, FindingSource
from drake_x.models.session import Session
from drake_x.scope import parse_target


# ----- task registration ----------------------------------------------------


def test_dedupe_task_is_registered() -> None:
    assert DedupeTask in ALL_TASKS


def test_dedupe_task_schema_includes_groups_canonical_and_duplicates() -> None:
    schema = DedupeTask.schema
    assert "groups" in schema
    group_schema = schema["groups"][0]
    assert "canonical_id" in group_schema
    assert "duplicate_ids" in group_schema
    assert "rationale" in group_schema


def test_dedupe_task_uses_existing_prompt_template() -> None:
    """The prompt file must exist on disk so the task loader doesn't crash."""
    template = DedupeTask().prompts_dir / DedupeTask.prompt_file
    assert template.exists()


# ----- WorkspaceStorage.update_finding_tags ---------------------------------


def _make_session_and_findings(workspace: Workspace) -> tuple[str, list[Finding]]:
    storage = WorkspaceStorage(workspace.db_path)
    target = parse_target("https://example.com/")
    session = Session(target=target, profile="passive")
    storage.legacy.save_session(session)

    findings = [
        Finding(
            title="Missing Strict-Transport-Security header",
            summary="HTTPS response has no HSTS",
            severity=FindingSeverity.MEDIUM,
            confidence=0.9,
            source=FindingSource.RULE,
            cwe=["CWE-319"],
            tags=["security-header"],
        ),
        Finding(
            title="Strict-Transport-Security missing",
            summary="No HSTS observed on the HTTPS response",
            severity=FindingSeverity.MEDIUM,
            confidence=0.9,
            source=FindingSource.RULE,
            cwe=["CWE-319"],
            tags=["security-header"],
        ),
        Finding(
            title="Missing Content-Security-Policy header",
            summary="No CSP observed",
            severity=FindingSeverity.LOW,
            confidence=0.9,
            source=FindingSource.RULE,
            cwe=["CWE-693"],
            tags=["security-header"],
        ),
    ]
    for f in findings:
        storage.save_finding(session.id, f)
    return session.id, findings


def test_update_finding_tags_persists_in_v2_row(tmp_path: Path) -> None:
    ws = Workspace.init("dedupe-storage", root=tmp_path)
    storage = WorkspaceStorage(ws.db_path)
    session_id, findings = _make_session_and_findings(ws)

    target = findings[1]
    new_tags = list(target.tags) + [f"duplicate-of:{findings[0].id}"]
    ok = storage.update_finding_tags(target.id, new_tags)
    assert ok is True

    reloaded = storage.load_findings(session_id)
    target_after = next(f for f in reloaded if f.id == target.id)
    assert any(t.startswith("duplicate-of:") for t in target_after.tags)


def test_update_finding_tags_returns_false_for_unknown_id(tmp_path: Path) -> None:
    ws = Workspace.init("dedupe-unknown", root=tmp_path)
    storage = WorkspaceStorage(ws.db_path)
    storage.legacy.save_session(
        Session(target=parse_target("example.com"), profile="passive")
    )
    ok = storage.update_finding_tags("f-deadbeef", ["nope"])
    assert ok is False


# ----- CLI: drake ai dedupe -------------------------------------------------


def test_dedupe_cli_dry_run_does_not_persist(tmp_path: Path, monkeypatch) -> None:
    ws = Workspace.init("dedupe-cli-dry", root=tmp_path)
    session_id, findings = _make_session_and_findings(ws)

    canonical_id = findings[0].id
    duplicate_id = findings[1].id

    fake_response = json.dumps(
        {
            "groups": [
                {
                    "canonical_id": canonical_id,
                    "duplicate_ids": [duplicate_id],
                    "rationale": "both describe the same missing HSTS header",
                }
            ]
        }
    )

    async def fake_generate(self, prompt: str, *, system: str | None = None) -> str:  # noqa: ARG001
        return fake_response

    runner = CliRunner()
    with patch.object(OllamaClient, "generate", new=fake_generate):
        result = runner.invoke(
            app,
            ["ai", "dedupe", session_id, "-w", str(ws.root)],
        )

    assert result.exit_code == 0, result.output
    assert "dedupe groups" in result.output
    assert canonical_id in result.output
    # Without --apply nothing should be persisted.
    storage = WorkspaceStorage(ws.db_path)
    reloaded = storage.load_findings(session_id)
    target = next(f for f in reloaded if f.id == duplicate_id)
    assert all(not t.startswith("duplicate-of:") for t in target.tags)


def test_dedupe_cli_apply_persists_tags(tmp_path: Path) -> None:
    ws = Workspace.init("dedupe-cli-apply", root=tmp_path)
    session_id, findings = _make_session_and_findings(ws)

    canonical_id = findings[0].id
    duplicate_id = findings[1].id

    fake_response = json.dumps(
        {
            "groups": [
                {
                    "canonical_id": canonical_id,
                    "duplicate_ids": [duplicate_id],
                    "rationale": "both describe the same missing HSTS header",
                }
            ]
        }
    )

    async def fake_generate(self, prompt: str, *, system: str | None = None) -> str:  # noqa: ARG001
        return fake_response

    runner = CliRunner()
    with patch.object(OllamaClient, "generate", new=fake_generate):
        result = runner.invoke(
            app,
            ["ai", "dedupe", session_id, "-w", str(ws.root), "--apply"],
        )

    assert result.exit_code == 0, result.output
    assert "applied 1 duplicate-of tag" in result.output

    storage = WorkspaceStorage(ws.db_path)
    reloaded = storage.load_findings(session_id)
    target = next(f for f in reloaded if f.id == duplicate_id)
    assert f"duplicate-of:{canonical_id}" in target.tags
    # The canonical finding must NOT be tagged.
    canonical = next(f for f in reloaded if f.id == canonical_id)
    assert not any(t.startswith("duplicate-of:") for t in canonical.tags)


def test_dedupe_cli_handles_session_with_no_findings(tmp_path: Path) -> None:
    ws = Workspace.init("dedupe-empty", root=tmp_path)
    storage = WorkspaceStorage(ws.db_path)
    session = Session(target=parse_target("example.com"), profile="passive")
    storage.legacy.save_session(session)

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["ai", "dedupe", session.id, "-w", str(ws.root)],
    )
    assert result.exit_code == 0
    assert "no findings to dedupe" in result.output


def test_dedupe_cli_apply_does_not_tag_canonical(tmp_path: Path) -> None:
    """If the model accidentally lists the canonical id in duplicate_ids, we skip it."""
    ws = Workspace.init("dedupe-self", root=tmp_path)
    session_id, findings = _make_session_and_findings(ws)

    canonical_id = findings[0].id
    fake_response = json.dumps(
        {
            "groups": [
                {
                    "canonical_id": canonical_id,
                    "duplicate_ids": [canonical_id],  # echo of the canonical id
                    "rationale": "self-loop",
                }
            ]
        }
    )

    async def fake_generate(self, prompt: str, *, system: str | None = None) -> str:  # noqa: ARG001
        return fake_response

    runner = CliRunner()
    with patch.object(OllamaClient, "generate", new=fake_generate):
        result = runner.invoke(
            app,
            ["ai", "dedupe", session_id, "-w", str(ws.root), "--apply"],
        )
    assert result.exit_code == 0
    assert "applied 0 duplicate-of tag" in result.output

    storage = WorkspaceStorage(ws.db_path)
    canonical = next(f for f in storage.load_findings(session_id) if f.id == canonical_id)
    assert all(not t.startswith("duplicate-of:") for t in canonical.tags)
