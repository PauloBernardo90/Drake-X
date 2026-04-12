# AI Auditability

Drake-X v1.0 audits AI usage across the platform, not just on the PE
exploit-assessment path.

## Scope

Audited paths in v1.0:

- `drake pe analyze --ai-exploit-assessment`
- generic `drake ai summarize|classify|next-steps|observations|draft-report`
- `drake ai dedupe`
- `drake assist start`
- workspace-aware engine AI triage paths used by recon/mission flows

All of these flow through the shared `drake_x.ai.audited_run.run_audited`
wrapper.

## Record Shape

Each audited invocation writes one JSON object per line to
`ai_audit/<task>.jsonl`.

Fields recorded:

- `task`
- `model`
- `timestamp`
- `prompt_sha256`
- `context_node_ids`
- `raw_response`
- `parsed`
- `truncation_notes`
- `ok`
- `error`
- `prompt_chars`
- `response_chars`

## What the Audit Guarantees

- an audit record is written on success
- an audit record is written when the local runtime is unreachable
- an audit record is written when parsing fails
- context node IDs are sorted and deduplicated before writing
- prompt hash is over the exact prompt text sent

The audit log therefore answers:

- what task ran
- what model was used
- what evidence context it used
- what the model answered
- whether the call succeeded

## Graph-Aware Context

PE exploit assessment uses bounded graph retrieval and records:

- graph-derived context node IDs
- truncation notes when the graph context is bounded

Generic `drake ai ...` tasks may run without graph retrieval. In that
case the audit record still exists, but `context_node_ids` may be empty.

## Reproducibility Notes

Deterministic surfaces:

- prompt hash for identical prompt text
- sorted context node IDs
- truncation note capture

Expected nondeterministic surfaces:

- model response text
- audit timestamps

Drake-X uses a non-zero model temperature by default, so auditability is
stronger than output determinism. The platform records what happened; it
does not claim the model will emit byte-identical answers across runs.

## Local-First Boundary

Audit data remains inside the workspace. Drake-X does not send prompts,
responses, or audit records to a remote provider.
