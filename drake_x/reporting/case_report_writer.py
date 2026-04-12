"""Multi-domain consolidated case report writer (v1.0).

Given a workspace, builds a :class:`CaseReport` by scanning persisted
evidence graphs + validation plans + running the correlator, then
renders a Markdown document that indexes every session and surfaces
cross-session signal. It does not replace the per-domain writers.
"""

from __future__ import annotations

from ..correlation import correlate_samples, load_all_graphs
from ..models.case_report import CaseReport, SessionSummary


def build_case_report(storage, *, workspace: str) -> CaseReport:
    graphs = load_all_graphs(storage)
    sessions_meta = {s.id: s for s in storage.legacy.list_sessions(limit=10_000)}

    sess_summaries: list[SessionSummary] = []
    for sid in sorted(graphs.keys()):
        graph = graphs[sid]
        meta = sessions_meta.get(sid)
        # Domain inference: pick the most common domain on the graph.
        domain = _dominant_domain(graph)
        sess_summaries.append(SessionSummary(
            session_id=sid,
            profile=getattr(meta, "profile", "?"),
            target_display=getattr(getattr(meta, "target", None), "canonical", "?"),
            domain=domain,
            node_count=len(graph.nodes),
            edge_count=len(graph.edges),
        ))
    sess_summaries.sort(key=lambda s: (s.domain, s.session_id))

    correlations = correlate_samples(storage, min_shared=2)
    corr_rows = correlations.model_dump(mode="json")
    external_sessions = {
        sid for sid, graph in graphs.items()
        if any(n.domain == "external" or n.data.get("external") for n in graph.nodes)
    }
    for row in corr_rows.get("correlations", []):
        src = row.get("source_session", "")
        dst = row.get("target_session", "")
        row["source_external"] = src in external_sessions
        row["target_external"] = dst in external_sessions
        row["external_touching"] = row["source_external"] or row["target_external"]

    plans: dict[str, dict] = {}
    for sid in sorted(graphs.keys()):
        plan = storage.load_validation_plan(sid)
        if plan is not None:
            plans[sid] = plan.model_dump(mode="json")

    return CaseReport(
        workspace=workspace,
        sessions=sess_summaries,
        correlations=corr_rows,
        validation_plans=plans,
    )


def render_case_report_markdown(report: CaseReport) -> str:
    lines: list[str] = [
        f"# Drake-X Case Report — workspace `{report.workspace}`",
        "",
        f"Sessions: **{len(report.sessions)}**  ·  "
        f"Correlations: **{len(report.correlations.get('correlations', []))}**  ·  "
        f"Plans persisted: **{len(report.validation_plans)}**",
        "",
        "## 1. Session Index",
        "",
    ]
    if report.sessions:
        lines.append("| Session | Domain | Profile | Target | Nodes | Edges | Flags |")
        lines.append("|---------|--------|---------|--------|-------|-------|-------|")
        for s in report.sessions:
            flags = "external" if s.profile == "ingest" or s.domain == "external" else "-"
            lines.append(
                f"| `{s.session_id[:12]}` | {s.domain or '-'} | {s.profile} | "
                f"{s.target_display[:40]} | {s.node_count} | {s.edge_count} | {flags} |"
            )
    else:
        lines.append("_No persisted sessions with evidence graphs._")
    lines.append("")

    lines.append("## 2. Cross-Session Correlations")
    lines.append("")
    correlations = report.correlations.get("correlations", [])
    if not correlations:
        lines.append("_No cross-session correlations surfaced._")
    else:
        lines.append("| Source | Target | Score | Shared | Flags |")
        lines.append("|--------|--------|-------|--------|-------|")
        for c in correlations:
            flags = "[external]" if c.get("external_touching") else "-"
            lines.append(
                f"| `{c['source_session'][:12]}` | `{c['target_session'][:12]}` | "
                f"{c['score']:.2f} | {len(c['shared'])} | {flags} |"
            )
    lines.append("")

    lines.append("## 3. Validation Plans")
    lines.append("")
    if not report.validation_plans:
        lines.append("_No validation plans persisted for this case._")
    else:
        for sid in sorted(report.validation_plans.keys()):
            plan = report.validation_plans[sid]
            items = plan.get("items", [])
            lines.append(f"### Session `{sid[:12]}` — {len(items)} item(s)")
            lines.append("")
            for it in items:
                lines.append(
                    f"- ({it.get('priority')}, {it.get('status')}) "
                    f"**{it.get('domain')}**: {it.get('hypothesis')}"
                )
            lines.append("")

    for c in report.caveats:
        lines.append(f"> {c}")
    lines.append("")
    return "\n".join(lines)


def _dominant_domain(graph) -> str:
    counts: dict[str, int] = {}
    for n in graph.nodes:
        counts[n.domain] = counts.get(n.domain, 0) + 1
    if not counts:
        return ""
    return max(counts.items(), key=lambda kv: kv[1])[0]
