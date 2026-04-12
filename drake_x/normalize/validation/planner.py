"""Build a validation plan from a session's Evidence Graph.

The planner turns indicator and artifact nodes into actionable
:class:`ValidationItem` entries — one per signal that warrants
dynamic or manual follow-up. It does not guess: every item is
backed by a concrete graph node, and the underlying node IDs
are recorded on the item.
"""

from __future__ import annotations

from ...models.evidence_graph import EvidenceGraph, NodeKind
from ...models.validation_plan import (
    Priority,
    ValidationItem,
    ValidationPlan,
)


def build_plan_for_session(storage, session_id: str) -> ValidationPlan:
    """Build a plan by walking the session's graph.

    Sources we currently cover (extending this is additive):

    - PE exploit indicators → one item per indicator (priority
      reflects severity; rationale cites evidence refs).
    - PE suspected shellcode → dynamic triage item per artifact.
    - PE protection-interaction → one item per assessment.
    - APK frida targets — surfaced as graph indicator nodes if the
      APK pipeline persisted them.
    - Ingested findings (domain=external) → one item each when trust
      is at least medium.
    """
    graph = storage.load_evidence_graph(session_id) or EvidenceGraph()
    items: list[ValidationItem] = []
    counter = 0

    for node in graph.nodes:
        if node.domain == "pe" and node.kind == NodeKind.INDICATOR and \
                "indicator:" in node.node_id:
            counter += 1
            sev = str(node.data.get("severity", "medium"))
            items.append(ValidationItem(
                item_id=f"v-{counter:03d}",
                domain="pe",
                hypothesis=f"Suspected {node.data.get('indicator_type', 'capability')} "
                            f"— {node.label}",
                rationale=(
                    f"Static indicator (confidence {node.data.get('confidence', 0.5):.2f}) "
                    f"backed by: {', '.join(node.data.get('evidence_refs_raw', [])[:3])}"
                    if node.data.get("evidence_refs_raw")
                    else "Static indicator derived from PE analysis."
                ),
                suggested_steps=[
                    "Execute sample in an instrumented sandbox",
                    "Set breakpoints on the cited imports",
                    "Capture runtime behavior and compare with static indicator",
                ],
                expected_evidence="Runtime observations confirming or refuting capability",
                suggested_tool="sandbox / debugger",
                priority=_severity_to_priority(sev),
                evidence_node_ids=[node.node_id],
            ))

        elif node.domain == "pe" and node.kind == NodeKind.ARTIFACT and \
                ":shellcode:" in node.node_id:
            counter += 1
            items.append(ValidationItem(
                item_id=f"v-{counter:03d}",
                domain="pe",
                hypothesis=f"Suspected shellcode at {node.data.get('source_location', '?')}",
                rationale=str(node.data.get("detection_reason", "Carved blob pending triage.")),
                suggested_steps=[
                    "Extract the artifact from the work directory",
                    "Inspect in an isolated debugger / emulator (no execution)",
                    "Classify: loader, stage-0, decoy, etc.",
                ],
                expected_evidence="Disassembly showing control flow / behaviour",
                suggested_tool="isolated debugger",
                priority=Priority.HIGH if node.data.get("confidence", 0) >= 0.6 else Priority.MEDIUM,
                evidence_node_ids=[node.node_id],
            ))

        elif node.domain == "pe" and "protection_interaction" in node.node_id:
            counter += 1
            items.append(ValidationItem(
                item_id=f"v-{counter:03d}",
                domain="pe",
                hypothesis=str(node.data.get("observed_capability", "")) or
                            "Protection interaction requires runtime validation",
                rationale=str(node.data.get("interaction_assessment", "")),
                suggested_steps=[
                    "Run under a debugger with the relevant protection toggled",
                    "Observe actual behavior, record findings",
                ],
                expected_evidence="Runtime trace",
                suggested_tool="debugger / sandbox",
                priority=_severity_to_priority(str(node.data.get("severity", "medium"))),
                evidence_node_ids=[node.node_id],
            ))

        elif node.domain == "external" and node.kind == NodeKind.FINDING:
            prov = node.data.get("provenance", {})
            trust = str(prov.get("trust", "medium"))
            if trust == "low":
                continue
            counter += 1
            items.append(ValidationItem(
                item_id=f"v-{counter:03d}",
                domain="external",
                hypothesis=node.label or "External finding requires validation",
                rationale=f"Imported via adapter '{prov.get('adapter', '?')}' "
                           f"from '{prov.get('source_tool', '?')}' (trust={trust})",
                suggested_steps=[
                    "Correlate with deterministic evidence in the graph",
                    "Re-run the originating analysis if sources are still available",
                ],
                expected_evidence="Confirmation from Drake-generated evidence",
                suggested_tool="drake correlate / drake graph query",
                priority=Priority.MEDIUM,
                evidence_node_ids=[node.node_id],
            ))

    # Deterministic order: priority high→low, then item_id.
    order = {Priority.HIGH: 0, Priority.MEDIUM: 1, Priority.LOW: 2}
    items.sort(key=lambda i: (order[i.priority], i.item_id))

    return ValidationPlan(session_id=session_id, items=items)


def _severity_to_priority(sev: str) -> Priority:
    s = sev.lower()
    if s in ("high", "critical"):
        return Priority.HIGH
    if s == "low":
        return Priority.LOW
    return Priority.MEDIUM
