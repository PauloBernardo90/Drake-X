"""v1.0 platform regression coverage.

One file, one test per headline capability — enough to prove the
platform surfaces work end-to-end. Specialized edge-case tests can
grow alongside each module's own test file later.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from drake_x.ai.audited_run import run_audited
from drake_x.correlation import correlate_samples, query_nodes
from drake_x.execution import LocalQueue, LocalWorker, new_job, register_handler
from drake_x.integrations.ingest import adapter_registry, ingest_file
from drake_x.models.elf import ElfAnalysisResult, ElfHeader, ElfImport, ElfMetadata
from drake_x.models.evidence_graph import (
    EdgeType,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)
from drake_x.models.external_evidence import ExternalEvidenceRecord, ExternalProvenance
from drake_x.models.validation_plan import (
    PlanStatus,
    Priority,
    ValidationItem,
    ValidationPlan,
)
from drake_x.normalize.binary.elf_normalize import build_elf_graph, classify_elf_imports
from drake_x.normalize.validation.planner import build_plan_for_session
from drake_x.reporting.case_report_writer import (
    build_case_report,
    render_case_report_markdown,
)
from drake_x.reporting.elf_report_writer import render_elf_markdown
from drake_x.reporting.validation_writer import render_validation_plan_markdown


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _workspace(tmp_path):
    from drake_x.core.workspace import Workspace
    ws = Workspace.init("test-ws", root=tmp_path)
    ws.ensure_directories()
    return ws


def _seed_session_with_graph(ws, session_id, graph):
    from drake_x.models.session import Session, SessionStatus
    from drake_x.models.target import Target

    target = Target(
        raw="sample",
        canonical="sample",
        target_type="domain",
        host="sample",
    )
    sess = Session(id=session_id, target=target, profile="test", status=SessionStatus.COMPLETED)
    ws.storage.legacy.save_session(sess)
    ws.storage.save_evidence_graph(session_id, graph)


def _pe_like_graph(sha="a" * 64, extra_import=None):
    g = EvidenceGraph()
    root = f"pe:{sha[:16]}:artifact"
    g.add_node(EvidenceNode(node_id=root, kind=NodeKind.ARTIFACT, domain="pe",
                             label="pe sample", data={"sha256": sha}))
    imp_id = f"pe:{sha[:16]}:import:kernel32.dll:VirtualAllocEx"
    g.add_node(EvidenceNode(
        node_id=imp_id, kind=NodeKind.EVIDENCE, domain="pe",
        label="import kernel32.dll!VirtualAllocEx",
        data={"dll": "kernel32.dll", "function": "VirtualAllocEx", "risk": "high"},
    ))
    g.add_edge(EvidenceEdge(source_id=imp_id, target_id=root,
                             edge_type=EdgeType.DERIVED_FROM))
    if extra_import:
        dll, func = extra_import
        nid = f"pe:{sha[:16]}:import:{dll}:{func}"
        g.add_node(EvidenceNode(
            node_id=nid, kind=NodeKind.EVIDENCE, domain="pe",
            label=f"import {dll}!{func}",
            data={"dll": dll, "function": func},
        ))
        g.add_edge(EvidenceEdge(source_id=nid, target_id=root,
                                 edge_type=EdgeType.DERIVED_FROM))
    return g


# ---------------------------------------------------------------------------
# Phase 1 — cross-sample correlation + global query
# ---------------------------------------------------------------------------


def test_correlation_surfaces_shared_imports(tmp_path):
    ws = _workspace(tmp_path)
    _seed_session_with_graph(ws, "sess-a", _pe_like_graph())
    _seed_session_with_graph(ws, "sess-b", _pe_like_graph(sha="b" * 64))
    report = correlate_samples(ws.storage)
    assert report.session_count == 2
    assert len(report.correlations) == 1
    c = report.correlations[0]
    bases = {s.basis for s in c.shared}
    assert "shared_import" in bases
    assert c.score > 0.0


def test_correlation_no_false_positives_on_unique_samples(tmp_path):
    ws = _workspace(tmp_path)
    _seed_session_with_graph(ws, "sess-a", _pe_like_graph())
    _seed_session_with_graph(ws, "sess-b",
        _pe_like_graph(sha="b" * 64, extra_import=("user32.dll", "OnlyHere")))
    # Force a graph whose only import is unique.
    g = EvidenceGraph()
    g.add_node(EvidenceNode(
        node_id="pe:c:artifact", kind=NodeKind.ARTIFACT, domain="pe",
        label="c", data={"sha256": "c" * 64},
    ))
    g.add_node(EvidenceNode(
        node_id="pe:c:import:advapi.dll:UniqueApi",
        kind=NodeKind.EVIDENCE, domain="pe",
        label="i", data={"dll": "advapi.dll", "function": "UniqueApi"},
    ))
    _seed_session_with_graph(ws, "sess-c", g)
    report = correlate_samples(ws.storage)
    # a↔b still correlates via VirtualAllocEx; c↔{a,b} should not appear
    src_tgt = {(c.source_session, c.target_session) for c in report.correlations}
    assert ("sess-a", "sess-b") in src_tgt or ("sess-b", "sess-a") in src_tgt
    assert not any("sess-c" in pair for pair in src_tgt)


def test_global_query_filters_by_kind_and_domain(tmp_path):
    ws = _workspace(tmp_path)
    _seed_session_with_graph(ws, "sess-a", _pe_like_graph())
    rows = query_nodes(ws.storage, kind="evidence", domain="pe")
    assert any(r["label"].startswith("import ") for r in rows)


# ---------------------------------------------------------------------------
# Phase 2 — external evidence ingestion
# ---------------------------------------------------------------------------


def test_json_adapter_is_registered():
    assert "json" in adapter_registry()


def test_ingest_preserves_provenance_on_every_record(tmp_path):
    ws = _workspace(tmp_path)
    payload = {
        "source_tool": "acme-sandbox",
        "records": [
            {"kind": "finding", "label": "sandbox hit", "data": {"severity": "high"}},
            {"kind": "indicator", "label": "C2 URL", "data": {"url": "http://evil.example"}},
        ],
    }
    p = tmp_path / "ingest.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    result = ingest_file(
        file=p, adapter_name="json", storage=ws.storage, session_id=None, trust="medium",
    )
    assert result.node_count >= 3  # root + 2 records
    graph = ws.storage.load_evidence_graph(result.session_id)
    assert graph is not None
    # Every non-root ingest node must carry provenance.
    for node in graph.nodes:
        if node.data.get("external") and node.node_id.startswith("ext:"):
            assert "provenance" in node.data
            prov = node.data["provenance"]
            assert prov["source_tool"] == "acme-sandbox"
            assert prov["adapter"] == "json"
            assert prov["trust"] == "medium"


def test_ingest_rejects_unknown_kinds_silently(tmp_path):
    ws = _workspace(tmp_path)
    payload = [
        {"kind": "BOGUS", "data": {}},
        {"kind": "finding", "label": "ok", "data": {}},
    ]
    p = tmp_path / "ingest.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    result = ingest_file(
        file=p, adapter_name="json", storage=ws.storage, session_id=None,
    )
    # Only the valid record + root node survive.
    assert result.node_count == 2


def test_ingest_root_id_is_deterministic_for_same_file(tmp_path):
    ws = _workspace(tmp_path)
    payload = [{"kind": "finding", "label": "ok", "data": {}}]
    p = tmp_path / "ingest.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    result_a = ingest_file(file=p, adapter_name="json", storage=ws.storage, session_id=None)
    result_b = ingest_file(file=p, adapter_name="json", storage=ws.storage, session_id=result_a.session_id)

    graph = ws.storage.load_evidence_graph(result_b.session_id)
    assert graph is not None
    roots = [
        n.node_id for n in graph.nodes
        if n.node_id.startswith(f"ingest:json:{result_a.session_id}:")
    ]
    assert len(roots) == 1


# ---------------------------------------------------------------------------
# Phase 3 — validation plan
# ---------------------------------------------------------------------------


def test_validation_plan_persists_and_loads(tmp_path):
    ws = _workspace(tmp_path)
    from drake_x.models.session import Session, SessionStatus
    from drake_x.models.target import Target
    target = Target(raw="s", canonical="s", target_type="domain", host="s")
    sess = Session(id="sess-x", target=target, profile="pe", status=SessionStatus.COMPLETED)
    ws.storage.legacy.save_session(sess)
    plan = ValidationPlan(session_id="sess-x", items=[
        ValidationItem(
            item_id="v-001", domain="pe",
            hypothesis="h", rationale="r",
            priority=Priority.HIGH, status=PlanStatus.PLANNED,
        ),
    ])
    ws.storage.save_validation_plan("sess-x", plan)
    loaded = ws.storage.load_validation_plan("sess-x")
    assert loaded is not None
    assert len(loaded.items) == 1
    assert loaded.items[0].priority == Priority.HIGH


def test_validation_plan_renders_markdown():
    plan = ValidationPlan(session_id="s" * 16, items=[
        ValidationItem(item_id="v-001", domain="pe",
                        hypothesis="Test hypothesis",
                        rationale="Test rationale",
                        suggested_steps=["step 1"],
                        evidence_node_ids=["pe:abc:indicator:inj:0"],
                        priority=Priority.HIGH),
    ])
    md = render_validation_plan_markdown(plan)
    assert "v-001" in md
    assert "Test hypothesis" in md
    assert "pe:abc:indicator:inj:0" in md


def test_validation_plan_built_from_pe_indicators(tmp_path):
    ws = _workspace(tmp_path)
    g = EvidenceGraph()
    g.add_node(EvidenceNode(
        node_id="pe:abc:artifact", kind=NodeKind.ARTIFACT, domain="pe",
        label="pe", data={"sha256": "a" * 64},
    ))
    g.add_node(EvidenceNode(
        node_id="pe:abc:indicator:injection_chain:0",
        kind=NodeKind.INDICATOR, domain="pe",
        label="Injection chain",
        data={
            "indicator_type": "injection_chain",
            "severity": "high", "confidence": 0.8,
            "evidence_refs_raw": ["VirtualAllocEx"],
        },
    ))
    _seed_session_with_graph(ws, "sess-1", g)
    plan = build_plan_for_session(ws.storage, "sess-1")
    assert any(item.priority == Priority.HIGH for item in plan.items)


# ---------------------------------------------------------------------------
# Phase 4 — platform-wide AI auditability
# ---------------------------------------------------------------------------


def test_run_audited_writes_record_on_success(tmp_path, monkeypatch):
    from drake_x.ai.audit import read_records
    from drake_x.ai.ollama_client import OllamaClient
    from drake_x.ai.tasks.base import AITask, TaskContext

    class StubTask(AITask):
        name = "stub"
        prompt_file = ""
        schema = {"x": "y"}

        def _build_prompt(self, context):  # bypass file-based template
            return "hello"

    async def fake_generate(self, prompt, system=None):  # noqa: ARG001
        return '{"x": 1}'

    monkeypatch.setattr("drake_x.ai.ollama_client.OllamaClient.generate", fake_generate)
    audit_dir = tmp_path / "ai_audit"
    result = run_audited(
        task=StubTask(), context=TaskContext(target_display="t", profile="p"),
        client=OllamaClient(base_url="http://x", model="m"),
        audit_dir=audit_dir,
        context_node_ids=["n1"], truncation_notes=["note"],
    )
    assert result.ok is True
    recs = read_records(audit_dir, "stub")
    assert len(recs) == 1
    assert recs[0].context_node_ids == ["n1"]
    assert recs[0].truncation_notes == ["note"]


def test_run_audited_records_failure(tmp_path, monkeypatch):
    from drake_x.ai.audit import read_records
    from drake_x.ai.ollama_client import OllamaClient
    from drake_x.ai.tasks.base import AITask, TaskContext

    class StubTask(AITask):
        name = "stub_fail"
        prompt_file = ""
        schema = {}

        def _build_prompt(self, context):
            return "q"

    async def exploding_generate(self, prompt, system=None):  # noqa: ARG001
        from drake_x.exceptions import AIUnavailableError
        raise AIUnavailableError("nope")

    monkeypatch.setattr("drake_x.ai.ollama_client.OllamaClient.generate", exploding_generate)
    audit_dir = tmp_path / "ai_audit"
    result = run_audited(
        task=StubTask(), context=TaskContext(target_display="t", profile="p"),
        client=OllamaClient(base_url="http://x", model="m"),
        audit_dir=audit_dir,
    )
    assert result.ok is False
    recs = read_records(audit_dir, "stub_fail")
    assert len(recs) == 1
    assert recs[0].ok is False


# ---------------------------------------------------------------------------
# Phase 5 — ELF first-class workflow
# ---------------------------------------------------------------------------


def _elf_fixture():
    r = ElfAnalysisResult(
        metadata=ElfMetadata(sha256="e" * 64, md5="m" * 32, file_size=1024),
        header=ElfHeader(bits=64),
        imports=[
            ElfImport(library="libc.so.6", symbol="execve"),
            ElfImport(library="libc.so.6", symbol="strcpy"),
        ],
    )
    r.import_risk_findings = classify_elf_imports(r.imports)
    return r


def test_elf_classifier_flags_execve():
    imports = [ElfImport(library="libc", symbol="execve")]
    risks = classify_elf_imports(imports)
    assert risks and risks[0]["category"] == "execution"
    assert risks[0]["risk"] == "high"


def test_elf_graph_builder_includes_artifact_and_imports():
    r = _elf_fixture()
    g = build_elf_graph(r)
    labels = [n.label for n in g.nodes]
    assert any("ELF sample" in l for l in labels)
    assert any("libc.so.6!execve" in l for l in labels)


def test_elf_report_renders():
    md = render_elf_markdown(_elf_fixture())
    assert "ELF Static Analysis Report" in md
    assert "execve" in md


def test_elf_cli_persists_graph_to_workspace(tmp_path):
    from typer.testing import CliRunner
    from drake_x.cli import app
    from drake_x.core.workspace import Workspace

    elf_file = tmp_path / "sample.elf"
    elf_file.write_bytes(
        b"\x7fELF"
        + b"\x02"
        + b"\x01"
        + b"\x01"
        + (b"\x00" * 9)
        + b"\x02\x00"
        + b"\x3e\x00"
        + b"\x01\x00\x00\x00"
        + b"\x00\x10\x40\x00\x00\x00\x00\x00"
        + (b"\x00" * 40)
    )
    ws = Workspace.init("elf-ws", root=tmp_path)
    result = CliRunner().invoke(app, ["elf", "analyze", str(elf_file), "-w", str(ws.root)])
    assert result.exit_code == 0

    sessions = ws.storage.legacy.list_sessions(limit=10)
    assert sessions
    graph = ws.storage.load_evidence_graph(sessions[0].id)
    assert graph is not None
    assert any(node.domain == "elf" for node in graph.nodes)


# ---------------------------------------------------------------------------
# Phase 6 — multi-domain case report
# ---------------------------------------------------------------------------


def test_case_report_indexes_sessions_and_correlations(tmp_path):
    ws = _workspace(tmp_path)
    _seed_session_with_graph(ws, "sess-a", _pe_like_graph())
    _seed_session_with_graph(ws, "sess-b", _pe_like_graph(sha="b" * 64))
    report = build_case_report(ws.storage, workspace="w")
    assert len(report.sessions) == 2
    md = render_case_report_markdown(report)
    assert "Drake-X Case Report" in md
    assert "Session Index" in md
    assert "Cross-Session Correlations" in md
    assert "sample" in md


# ---------------------------------------------------------------------------
# Phase 7 — distributed execution foundation
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_handlers(monkeypatch):
    """Keep handler registry per-test (prevents cross-test leakage)."""
    from drake_x.execution import worker as w
    old = dict(w._HANDLERS)
    w._HANDLERS.clear()
    yield
    w._HANDLERS.clear()
    w._HANDLERS.update(old)


def test_local_queue_drains_job(tmp_path):
    ws = _workspace(tmp_path)
    q = LocalQueue(ws.storage)

    seen: list[dict] = []

    @register_handler("test.echo")
    def echo(payload):
        seen.append(payload)

    q.enqueue(new_job("test.echo", {"a": 1}))
    n = LocalWorker(q).drain()
    assert n == 1
    assert seen == [{"a": 1}]
    rows = ws.storage.load_jobs()
    assert rows and rows[0]["status"] == "succeeded"


def test_job_failure_retries_then_abandons(tmp_path):
    ws = _workspace(tmp_path)
    q = LocalQueue(ws.storage)

    @register_handler("test.boom")
    def boom(payload):
        raise RuntimeError("boom")

    q.enqueue(new_job("test.boom", {}, max_attempts=2))
    worker = LocalWorker(q)
    worker.run_once()    # attempt 1 → retry (back to queued)
    worker.run_once()    # attempt 2 → abandoned
    rows = ws.storage.load_jobs()
    assert rows[0]["status"] == "abandoned"
    assert rows[0]["attempts"] == 2


def test_unknown_kind_is_abandoned_immediately(tmp_path):
    ws = _workspace(tmp_path)
    q = LocalQueue(ws.storage)
    q.enqueue(new_job("test.nothing", {}, max_attempts=5))
    LocalWorker(q).run_once()
    rows = ws.storage.load_jobs()
    assert rows[0]["status"] == "abandoned"
    assert "no handler" in rows[0]["error"]


# ---------------------------------------------------------------------------
# Phase 8 — version bump
# ---------------------------------------------------------------------------


def test_version_is_v1():
    import drake_x
    assert drake_x.__version__ == "1.0.0"


# ---------------------------------------------------------------------------
# Model validation sanity
# ---------------------------------------------------------------------------


def test_external_evidence_rejects_missing_provenance():
    with pytest.raises(ValidationError):
        ExternalEvidenceRecord(kind="finding", label="x", data={})  # no provenance
