# Drake-X Graph Analysis

See also: [`evidence-model.md`](evidence-model.md),
[`architecture.md`](architecture.md), [`ai-auditability.md`](ai-auditability.md)

The Evidence Graph is the canonical analysis surface in Drake-X v1.0.
Graphs are persisted in SQLite per session and then reused for:

- `drake graph show` — session-local inspection
- `drake graph query` — workspace-wide node query
- `drake correlate run` — cross-sample evidence correlation
- AI context building
- structured validation planning
- multi-domain case reporting

## `drake graph show`

Inspect one persisted session graph:

```bash
drake graph show <session-id> -w my-engagement
drake graph show <session-id> -w my-engagement --format summary
drake graph show <session-id> -w my-engagement --format json
drake graph show <session-id> -w my-engagement --node <node-id> --depth 2
drake graph show <session-id> -w my-engagement --kind indicator
drake graph show <session-id> -w my-engagement --edge supports
```

This is for analyst navigation inside one session.

## `drake graph query`

Query nodes across every persisted graph in the workspace:

```bash
drake graph query -w my-engagement --kind indicator --domain pe
drake graph query -w my-engagement --label VirtualAllocEx
drake graph query -w my-engagement --data evil.example --format json
drake graph query -w my-engagement --min-confidence 0.7
```

Filters are deterministic and additive:

- `--kind`
- `--domain`
- `--label`
- `--data`
- `--min-confidence`

Output is ordered by session, then node ID.

## How Graphs Enter the Store

Persisted graph-producing workflows in v1.0:

- `drake pe analyze`
- `drake apk analyze`
- `drake elf analyze`
- supporting collection sessions
- `drake ingest evidence`

Imported evidence enters with `domain="external"` and mandatory
provenance under `node.data["provenance"]`.

## Design Properties

- **Deterministic IDs where applicable.** Drake-generated node IDs are
  stable across re-runs for identical evidence.
- **Bounded AI serialization.** Graph-to-prompt context is capped by
  nodes, edges, and characters.
- **Faithful provenance.** Edges represent observed derivation or
  support only.
- **Queryable at workspace scope.** Graphs are not just exports; they
  are persisted platform state.

## What v1.0 Correlation Uses

Cross-sample correlation currently derives workspace-level links from
persisted graph evidence. Supported bases:

- shared imports
- shared shellcode prefixes
- shared indicator clusters
- shared protection profiles
- shared IOC values

The output is observational. Shared graph evidence is surfaced with the
exact node IDs on both sides; Drake-X does not claim common authorship
or campaign ownership from correlation alone.
