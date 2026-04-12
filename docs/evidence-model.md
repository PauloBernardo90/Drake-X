# Drake-X Evidence Model

See also: [`graph-analysis.md`](graph-analysis.md),
[`ingestion.md`](ingestion.md), [`validation-plan.md`](validation-plan.md)

Drake-X v1.0 uses the Evidence Graph as the shared data model across
domain analysis, imported evidence, AI context building, validation
planning, and case reporting.

## Core Node Kinds

| Kind | Meaning |
|------|---------|
| `artifact` | a sample, file, carved blob, or ingest run root |
| `finding` | a surfaced analytic or rule-based conclusion |
| `indicator` | an observable such as URL, domain, or exploit signal |
| `evidence` | supporting structured fact such as import, section, permission |
| `protection` | mitigation or anti-analysis state |
| `campaign` | similarity/campaign-style assessment |

Every node carries:

- `node_id`
- `kind`
- `domain`
- `label`
- `data`

## Edge Types

| Type | Meaning |
|------|---------|
| `derived_from` | node was derived from another entity |
| `supports` | node provides evidence for another node |
| `related_to` | two nodes are related but not in a strict derivation chain |
| `duplicate_of` | deduplicated semantic duplicate |
| `contradicts` | explicit conflict |

## Domains

The current graph spans:

- `pe`
- `apk`
- `elf`
- `external`
- supporting collection domains such as `web`, `recon`, `api`

This allows case-level aggregation without inventing a second evidence
store.

## Persistence

Each session graph is stored in SQLite:

```sql
CREATE TABLE evidence_graphs (
  session_id TEXT PRIMARY KEY,
  graph_json TEXT NOT NULL,
  node_count INTEGER NOT NULL,
  edge_count INTEGER NOT NULL
);
```

Primary access path:

```python
storage.save_evidence_graph(session_id, graph)
graph = storage.load_evidence_graph(session_id)
```

## External Evidence

Imported evidence is first-class, but never conflated with Drake-
generated evidence. External records are normalized into graph nodes
with:

- `domain = "external"`
- `external = true`
- provenance block under `data["provenance"]`

Provenance includes:

- source tool
- source file
- adapter
- trust level
- ingestion timestamp
- notes

## Evidence vs Inference

The graph may carry both deterministic evidence and analytical outputs.
Downstream consumers must preserve that distinction:

- parser/tool outputs are evidence
- heuristic/analytic outputs are assessments
- AI outputs are inference
- imported outputs remain external evidence until validated

This distinction is surfaced in report writers and validation planning.

## Validation Plans

Validation plans are not a parallel evidence model. They are a derived
view over persisted graph state. Each `ValidationItem` stores the node
IDs that justify the hypothesis so analysts can trace directly from a
plan entry back to graph evidence.

## Correlation

Workspace-level correlation is also a derived view over the persisted
graph store. Correlation output records the exact source and target node
IDs that matched; it never creates hidden evidence.
