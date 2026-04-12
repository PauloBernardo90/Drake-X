# External Evidence Ingestion

Drake-X v1.0 can ingest external evidence into the workspace Evidence
Graph while preserving provenance.

## CLI

```bash
drake ingest list-adapters
drake ingest list-producers -w my-engagement
drake ingest register-producer sandbox-prod -w my-engagement --trust high
drake ingest evidence ./sandbox.json -w my-engagement --type json
drake ingest evidence ./sandbox.json -w my-engagement --type json --session <session-id> \
  --merge-into-analysis
drake ingest evidence ./sandbox.json -w my-engagement --trust high
```

`--merge-into-analysis` is not sufficient by itself. In release
workspaces, merging imported evidence into a non-`ingest` session is
blocked by default and requires a workspace policy opt-in.

## Adapter Contract

Adapters normalize external records into:

- `finding`
- `indicator`
- `evidence`
- `artifact`

Every imported record must carry provenance:

- source tool
- source file
- adapter
- requested trust
- effective trust
- attestation status
- registry trust, when present
- ingestion timestamp
- notes

Drake-X adapters translate or skip. They do not invent data.

## Current Adapter

v1.0 ships one concrete adapter:

- `json`

Accepted shapes:

1. top-level list of records
2. top-level object with `records` plus producer metadata

## Persistence Model

Imported records are merged into the session graph with:

- `domain = "external"`
- `external = true`
- provenance stored under `data["provenance"]`

If no session is provided, Drake-X creates an ingest-only session.

## Boundaries

- imported evidence is not treated as Drake-generated evidence
- trust is enforced as an **effective** value, not accepted as a
  self-declared claim
- unregistered producers are downgraded to `low`
- `--trust high` is rejected unless the producer is registered in the
  workspace at `high`
- low-trust imported findings are not surfaced by the v1.0 validation
  planner
- merge into an analysis session is disabled by default in release
  workspaces even when `--session` is provided

## Producer Registry

Drake-X uses a workspace-local producer registry stored in
`workspace.toml` under `ingest_producers`.

- `drake ingest register-producer <source_tool> -w <workspace> --trust <level>`
- `drake ingest unregister-producer <source_tool> -w <workspace>`
- `drake ingest list-producers -w <workspace>`

This is a local attestation control, not cryptographic signing. It
prevents operators from accidentally treating arbitrary external JSON as
high-trust evidence and gives downstream consumers an effective trust
value they can reason about deterministically.
