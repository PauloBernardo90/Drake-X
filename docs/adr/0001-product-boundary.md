# ADR-0001: Drake-X Product Boundary

## Status
Accepted

## Context
`Drake-X` is being built as a local CLI assistant for authorized security assessments. The project is inspired by modern AI-assisted security tooling, but there is a risk of unintentionally evolving from a conservative reconnaissance and validation assistant into an offensive security framework.

That boundary must be explicit in the repository so future contributors do not gradually introduce features that change the product's nature.

## Decision
`Drake-X` is defined as a `Recon Assistant` with limited `Validation Platform` characteristics.

It is not an `Offensive Security Framework`.

The system may:
- accept an IP, CIDR, domain, or URL
- orchestrate locally installed reconnaissance tools
- normalize tool output into structured artifacts
- store sessions, tool results, artifacts, and findings
- use a local Ollama model for defensive triage and summarization
- generate reports
- perform safe, conservative, non-destructive validation checks when explicitly designed as such

The system must not:
- automate exploitation
- generate or execute payloads
- attempt credential attacks or brute force
- implement persistence, evasion, lateral movement, or post-exploitation
- allow the LLM to execute arbitrary commands
- allow the LLM to select tools outside a fixed, code-defined registry and policy
- optimize for compromise, access, or offensive progression

## Architectural Implications
The architecture is constrained accordingly.

Allowed core components:
- target parsing and scope validation
- tool registry with fixed allowlisted tools
- conservative orchestrator
- normalizers that produce facts, not attack steps
- SQLite persistence for evidence and findings
- local AI analysis for evidence triage only
- reporting and auditability

Disallowed component patterns:
- exploit engine
- payload manager
- foothold/session manager for compromised targets
- autonomous planner that selects arbitrary offensive actions
- persistence/evasion modules
- any workflow whose primary success metric is access or impact on the target

## Product Framing
`Drake-X` exists to answer:
- what is exposed
- what is observable
- what likely deserves analyst review
- what safe next investigative steps should be considered

`Drake-X` does not exist to answer:
- how to gain access
- which payload to run
- how to escalate privileges
- how to persist or evade detection

## Consequences
Positive:
- clearer scope for contributors
- lower risk of accidental product drift
- safer default behavior
- simpler architecture and testing model
- better alignment with evidence-first reporting workflows

Negative:
- the product will intentionally exclude capabilities some offensive tools include
- some users may expect more aggressive automation than the project will provide
- validation features must be reviewed carefully to ensure they remain non-destructive

## Guardrails for Future Changes
Any proposed feature should be rejected or escalated for review if it:
- turns findings into exploit attempts
- introduces payload logic
- stores offensive operational state
- gives the AI freedom to choose arbitrary commands
- measures success by compromise rather than evidence quality

If a future proposal crosses these boundaries, it requires a new ADR rather than an incremental change under the current architecture.
