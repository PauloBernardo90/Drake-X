# Drake-X Architecture

See also: [`README.md`](README.md), [`graph-analysis.md`](graph-analysis.md),
[`evidence-model.md`](evidence-model.md), [`ai-auditability.md`](ai-auditability.md),
[`ingestion.md`](ingestion.md), [`validation-plan.md`](validation-plan.md),
[`native-analysis.md`](native-analysis.md), [`reporting.md`](reporting.md)

Drake-X v1.0 is a workspace-level, evidence-driven malware analysis
platform. The architectural center of gravity is the persisted Evidence
Graph in SQLite. Analysis pipelines, ingestion adapters, validation
plans, correlations, AI tasks, and reporting all operate over that
persisted evidence surface.

## Design Principles

- **Evidence over assumptions.** Deterministic evidence is persisted
  first; interpretation is layered on top and labeled explicitly.
- **Human-in-the-loop.** Drake-X produces findings, plans, and
  candidate outputs. It does not autonomously execute validation steps
  or weaponize evidence.
- **Local-first.** Analysis, graph persistence, correlation, and AI
  audit logging happen on the operator's host.
- **Reproducible where applicable.** Graph IDs, graph serialization,
  STIX IDs, candidate YARA timestamps, and cross-sample correlation
  outputs are deterministic for identical evidence.
- **Auditability by default.** AI calls, workspace runs, and queue/job
  history are stored locally as inspectable artifacts.

## Platform Layers

```text
CLI (drake_x.cli)
  -> Workspace / config resolution (drake_x.core.workspace)
  -> Storage facade (drake_x.core.storage)
  -> Domain analysis / ingestion / planning modules
  -> Evidence Graph persistence in SQLite
  -> Correlation / query / reporting / AI audit consumers
```

## Workspace Model

Each workspace lives under:

```text
~/.drake-x/workspaces/<name>/
  workspace.toml
  scope.yaml
  drake.db
  runs/
  audit.log
```

`workspace.toml` stores operator-local configuration such as Ollama
model and VirusTotal key. `drake.db` stores sessions, findings,
persisted evidence graphs, validation plans, and job history.

## Storage Model

`drake_x.core.storage.WorkspaceStorage` composes the legacy session
store with additive v1.x tables. Important persisted surfaces:

- `evidence_graphs` — canonical JSON-serialized graph per session
- `validation_plans` — one persisted structured plan per session
- `jobs` — experimental queue/job history
- `finding_extras` — extended finding metadata
- `scope_assets` — scope snapshot per session

This means graph consumers do not need to re-run analysis; they read the
workspace database directly.

## Domain Workflows

### PE

`drake pe analyze` remains the most feature-rich domain:

- static PE parsing
- bounded exploit-awareness
- graph-first ingestion
- optional AI exploit assessment
- optional candidate YARA/STIX outputs

PE writes `pe_graph.json` and also persists the graph to SQLite when a
workspace is used.

### APK

`drake apk analyze` builds an evidence graph from manifest, behaviors,
network indicators, protections, enrichments, and Frida validation
targets. Findings and graph are persisted when run in a workspace.

### ELF / Native

`drake elf analyze` is a first-class v1.0 workflow for ELF binaries.
The current scope is intentionally conservative:

- ELF header and section parsing
- imported symbol inventory
- protection profile (NX, PIE, RELRO, canary, FORTIFY)
- deterministic import-risk classification
- Evidence Graph output and persistence

Exploit-awareness parity with PE is not claimed for ELF in v1.0.

## External Evidence Ingestion

`drake ingest evidence` normalizes external outputs into the same graph
model. Every imported node carries:

- `domain = "external"`
- mandatory provenance under `node.data["provenance"]`
- `external = true`

Imported evidence is therefore always distinguishable from Drake-
generated evidence.

## Evidence Graph

The Evidence Graph is the canonical integration bus:

- per-session graph persisted in SQLite
- deterministic node IDs for Drake-generated domain entities
- queryable through `drake graph show` and `drake graph query`
- consumed by AI tasks, case reporting, validation planning, and
  cross-sample correlation

The graph now spans PE, APK, ELF, supporting collection, and imported
external evidence.

## Cross-Sample Correlation

`drake_x.correlation` loads every persisted graph in the workspace and
computes deterministic pairwise correlations. Current bases:

- shared imports
- shared shellcode prefixes
- shared indicator clusters
- shared protection profiles
- shared IOC values

Correlation output is observational. It records exactly which node IDs
matched; it does not claim attribution.

## Validation Plans

`drake validate plan` walks a persisted graph and emits a structured,
multi-domain analyst plan. Items are hypotheses backed by evidence node
IDs, with rationale, suggested steps, expected evidence, tool hints, and
priority.

Plans are persisted in SQLite and can be exported to Markdown. They are
not executable workflows.

## AI Layer

The AI layer remains local-first through Ollama. In v1.0:

- PE exploit assessment still uses graph retrieval
- generic `drake ai ...` tasks also run through the shared audited path
- every audited call records prompt hash, model, context node IDs,
  raw response, parsed response, and truncation notes when available

Audit records are append-only JSONL files under `ai_audit/`.

## Reporting

Drake-X ships two reporting tiers:

- per-session reporting: technical Markdown, executive Markdown, JSON,
  manifest, evidence index, domain-specific writers
- case-level reporting: `drake report case`, aggregating sessions,
  correlations, and persisted validation plans across the workspace

Candidate detection outputs remain PE-specific in v1.0.

## Execution Foundation

`drake_x.execution` provides a minimal job/queue/worker abstraction:

- `Job`
- `LocalQueue`
- `LocalWorker`
- handler registry

It is persisted in SQLite and intended as the seam for future remote
execution backends. v1.0 ships only the local experimental foundation.

## Boundaries

Drake-X does not:

- generate exploits
- optimize payloads
- provide bypass guidance
- auto-execute validation plans
- equate shared evidence with attribution

Those boundaries are enforced in both product surface and
documentation.
