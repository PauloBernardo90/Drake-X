# AI Auditability (v0.9)

Drake-X is evidence-first. That discipline must extend to the AI layer:
every LLM call has to be reproducible and inspectable by the operator
who ran it. v0.9 introduces the audit primitives required.

## Current scope (v0.9)

Audit logging is wired for the **PE exploit-assessment task**
(`drake pe analyze --ai-exploit-assessment`). The generic `drake ai …`
command family does not yet audit; extension to all AI task entry
points is scheduled for v1.0. Do not assume an AI answer came through
an audited path unless it was produced by the PE path.

## What is recorded

Each audited AI task invocation writes one line to
`<work_dir>/ai_audit/<task>.jsonl`. Each line is a JSON object with:

- `task` — task name (e.g. `exploit_assessment`)
- `model` — Ollama model identifier used
- `timestamp` — ISO-8601 UTC
- `prompt_sha256` — SHA-256 of the exact text sent to the model
- `context_node_ids` — sorted, deduplicated list of Evidence Graph
  node IDs the prompt was built from
- `raw_response` — the model's response as received
- `parsed` — the structured JSON extracted from the response, or
  `null` if extraction failed
- `truncation_notes` — any caps that bit during context building
- `ok`, `error` — success flag and error message
- `prompt_chars`, `response_chars` — size for quick scans

The file is append-only. Records are written even when the model is
unreachable or returns non-JSON — auditability must not depend on the
model answering correctly.

## Reproducibility

Because `prompt_sha256` is over the exact bytes sent and
`context_node_ids` is sorted and deduplicated, two runs over the same
sample produce the same prompt hash and the same context ID list. If
a re-run produces a different hash, something upstream (new evidence,
different graph state, different model config) has changed.

This does **not** guarantee the model returns the same response — local
LLM inference is non-deterministic at temperature > 0. Drake-X sends
`temperature=0.2` by default; for stricter reproducibility, operators
can drop it to `0` via Ollama's model config.

## Inspecting an audit trail

The log is plain JSONL. Example:

```bash
jq . work/ai_audit/exploit_assessment.jsonl | less
```

The programmatic reader is
`drake_x.ai.audit.read_records(audit_dir, task)`. It tolerates:

- unknown future fields (forward-compatible)
- malformed lines (skipped with a warning)

## Bounded context

Context is built by `drake_x.ai.context_builder.build_pe_exploit_context`.
Bounds are explicit and configurable:

- `max_nodes` (default 30) — graph nodes included
- `max_edges` (default 60)
- `max_chars` (default 4000) — character budget on the serialized graph
- `max_evidence_items` (default 12) — flat evidence items

When any bound is hit, the builder records a truncation note such as
`graph truncated: 12/18 seed nodes retained (max_nodes=30)`. That note
becomes part of the audit record, so the operator can see that
some evidence did not reach the prompt.

## Non-goals

- This is not a full AI eval harness. It does not score model
  outputs or compute agreement metrics.
- It does not store prompts outside the workspace. Nothing is sent
  anywhere.
- It does not attempt to redact the prompt. The operator owns the
  workspace directory; access control is filesystem-level.
