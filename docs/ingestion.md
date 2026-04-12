# External Evidence Ingestion

Drake-X v1.0 can ingest external evidence into the workspace Evidence
Graph while preserving provenance.

## CLI

```bash
drake ingest list-adapters
drake ingest evidence ./sandbox.json -w my-engagement --type json
drake ingest evidence ./sandbox.json -w my-engagement --type json --session <session-id>
drake ingest evidence ./sandbox.json -w my-engagement --trust high
```

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
- trust
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
- trust level is preserved; it is not silently upgraded
- low-trust imported findings are not surfaced by the v1.0 validation
  planner
