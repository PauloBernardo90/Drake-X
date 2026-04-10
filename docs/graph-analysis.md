# Drake-X Graph Analysis

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`evidence-model.md`](evidence-model.md), [`usage.md`](usage.md)

## Overview

Drake-X v0.5 introduces graph-aware intelligence: the ability for
analysts and AI tasks to explore structured relationships between
findings, artifacts, indicators, and assessments through the Evidence
Graph.

## `drake graph show`

```bash
# ASCII view — readable on dark Kali terminals
drake graph show <session-id> -w my-engagement

# Statistical summary
drake graph show <session-id> -w my-engagement --format summary

# JSON export
drake graph show <session-id> -w my-engagement --format json -o graph.json

# Focus on a specific node's neighborhood
drake graph show <session-id> -w my-engagement --node apk:behavior:0:dropper --depth 2

# Filter by node kind
drake graph show <session-id> -w my-engagement --findings
drake graph show <session-id> -w my-engagement --indicators
drake graph show <session-id> -w my-engagement --kind protection

# Filter by edge type
drake graph show <session-id> -w my-engagement --edge supports
```

## Graph-Aware AI

When a session has a persisted evidence graph, AI tasks automatically
receive a serialized graph neighborhood in the prompt alongside the
flat evidence list. This provides the model with:

- node-to-node relationships (which finding derived from which artifact)
- supporting evidence chains (which permission supports which behavior)
- cross-domain links (when APK and web indicators are in the same graph)

The graph context is:
- **Bounded** — limited by max_nodes, max_edges, max_chars
- **Deterministic** — identical graphs produce identical serializations
- **Faithful** — only relationships in the graph appear; nothing invented
- **Fallback-safe** — if no graph exists, AI uses flat evidence (v0.3 behavior)

## How Graphs Are Built

### Web/Recon Sessions

The engine automatically builds an evidence graph after each recon run:
- Root node: the session target
- Artifact nodes: one per tool output (curl, nmap, dig, etc.)
- Finding nodes: one per finding (HSTS missing, CSP missing, etc.)
- Edges: `derived_from` (artifact→target), `supports` (artifact→finding),
  `related_to` (finding→target), `duplicate_of` (from dedupe tags)

### APK Analysis

`drake apk analyze` builds a richer graph:
- Root: the APK sample
- Permissions, behaviors, indicators, obfuscation traits, protections,
  campaigns as separate node kinds
- Cross-category `supports` edges linking permissions to exfiltration
  findings, network IOCs to communication behaviors, behaviors to campaigns

## Design Principles

- **Evidence over assumptions.** Every edge is derived from a tool
  output or parser result. No edges are speculatively created.
- **Human-in-the-loop.** The graph is a navigational aid, not an
  autonomous decision maker. The analyst uses `drake graph show` to
  explore and validate.
- **Reproducibility.** Graphs are persisted in SQLite per-session and
  deterministically ordered. Copy the workspace, get the same graph.
- **Local-first.** All graph construction, querying, and rendering
  happens locally. No external services involved.
