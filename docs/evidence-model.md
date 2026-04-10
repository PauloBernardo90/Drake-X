# Drake-X Evidence Model

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`graph-analysis.md`](graph-analysis.md), [`architecture.md`](architecture.md)

## Overview

Drake-X v0.4 introduces the **Evidence Graph** — a structured
representation of relationships between findings, artifacts, indicators,
and assessments produced during an analysis session.

The graph enables:

- **Cross-domain correlation** — linking APK behavior indicators to
  network IOCs to campaign assessments in one traversable structure.
- **Provenance tracing** — following a finding back through every
  artifact and tool result that contributed to it.
- **AI reasoning context** — providing the local LLM with structured
  relationships rather than flat lists.
- **Analyst navigation** — answering "what evidence supports this
  conclusion?" without reading the full report.

## Node types

| Kind | Description | Example |
|------|-------------|---------|
| `artifact` | A raw tool output or ingested file | The APK sample, a session's curl result |
| `finding` | A detected behavior or pattern | "DexClassLoader usage", "missing HSTS" |
| `indicator` | A network IOC or observable | URL, IP address, domain |
| `evidence` | A supporting fact (permission, trait) | "READ_SMS permission", "identifier renaming" |
| `protection` | An anti-analysis protection | "root detection observed" |
| `campaign` | A campaign similarity assessment | "consistent with dropper" |

Every node carries:
- `node_id` — unique, prefixed by domain (e.g. `apk:behavior:0:dropper`)
- `kind` — one of the types above
- `domain` — the analysis domain (`apk`, `web`, `recon`, `api`)
- `label` — human-readable short name
- `data` — arbitrary structured metadata

## Edge types

| Type | Meaning | Example |
|------|---------|---------|
| `derived_from` | B was extracted from A | Behavior → Sample |
| `supports` | A provides evidence for B | Permission → Exfiltration finding |
| `related_to` | A and B are related | Campaign → Sample |
| `duplicate_of` | A is a duplicate of B | Finding A = Finding B |
| `contradicts` | A and B conflict | (reserved for future use) |

Every edge carries:
- `source_id` / `target_id` — node references
- `edge_type` — one of the types above
- `confidence` — 0.0 to 1.0
- `notes` — optional free text

## How the graph is built

### APK domain

The `build_apk_evidence_graph()` function in
`drake_x/normalize/apk/graph_builder.py` takes an `ApkAnalysisResult`
and produces a graph with:

- One root `artifact` node for the sample
- `evidence` nodes for each permission
- `finding` nodes for each behavior indicator
- `indicator` nodes for each network IOC
- `evidence` nodes for obfuscation traits
- `protection` nodes for observed protections
- `campaign` nodes for matching campaign assessments
- `derived_from` edges linking everything to the root
- `supports` edges linking permissions to exfiltration findings,
  network IOCs to communication behaviors, behaviors to campaigns

### Web domain (future)

The existing `Finding` model already carries `evidence` backrefs.
A future `build_web_evidence_graph()` will convert web sessions into
the same graph format for unified cross-domain reasoning.

## Persistence

The graph is stored in the `evidence_graphs` SQLite table:

```sql
CREATE TABLE IF NOT EXISTS evidence_graphs (
    session_id TEXT PRIMARY KEY,
    graph_json TEXT NOT NULL,
    node_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL
);
```

Save and load via `WorkspaceStorage`:

```python
storage.save_evidence_graph(session.id, graph)
graph = storage.load_evidence_graph(session.id)
```

The graph is also written as `evidence_graph.json` in the session's
output directory for offline inspection.

## Serialization

```python
graph.to_json(indent=2)      # JSON string
graph.to_dict()               # dict for embedding in reports
EvidenceGraph.from_dict(data) # reconstruct from dict
```

## Querying

```python
graph.get_node("apk:behavior:0:dropper")
graph.edges_from("apk:behavior:0:dropper")
graph.edges_to("apk:sample:abcd1234")
graph.neighbors("apk:sample:abcd1234")
graph.subgraph("apk")
graph.nodes_by_kind(NodeKind.FINDING)
graph.stats()
```

## Design Principles

- **Evidence over assumptions.** Every edge must be justified by a
  tool output or parser result. No edges are created speculatively.
- **Domain isolation.** Each domain prefixes its node IDs. A unified
  graph can merge multiple domain subgraphs without collisions.
- **Append-only.** Nodes and edges are added during analysis but never
  removed. The graph is a complete record of everything the analysis
  observed.
- **Serializable.** The graph round-trips through JSON for storage,
  export, and cross-host reproducibility.
