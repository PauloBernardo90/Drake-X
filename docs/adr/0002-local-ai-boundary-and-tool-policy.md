# ADR-0002: Local AI Boundary and Tool Policy

## Status
Accepted

## Context
`Drake-X` uses a local language model to help summarize and prioritize reconnaissance evidence. This adds value, but it also creates two risks:

- the AI layer could be treated as an operator instead of an analyst
- the AI layer could be allowed to influence tool execution beyond safe, deterministic policy

To keep the product aligned with its intended role, the boundaries between orchestration logic, tool policy, and AI behavior must be explicit.

## Decision
`Drake-X` will use AI as a local evidence-analysis component only.

The AI layer may:
- consume normalized artifacts produced by approved tools
- summarize observations
- correlate evidence from multiple tools
- identify likely technologies or services when supported by evidence
- highlight weak signals or areas worth manual review
- recommend safe next investigative steps
- attach confidence and caveats

The AI layer must not:
- execute tools directly
- request arbitrary command execution
- choose tools outside the fixed registry
- modify runtime policy
- generate payloads or exploitation guidance
- optimize toward compromise or operational success

Tool execution authority remains entirely in code-defined orchestration and policy, not in model output.

## Tool Policy
All executable tooling in `Drake-X` must be explicitly registered in code.

Tool policy requirements:
- tools must be allowlisted in the tool registry
- each tool must declare supported profiles
- each tool must declare supported target types
- each tool must build commands from safe argument lists
- each tool must execute without shell injection risk
- each tool must return structured execution metadata
- missing tools must degrade gracefully
- non-zero or degraded runs must surface provenance

No model output may expand this registry at runtime.

## AI Boundary
The AI integration is local-first and constrained.

AI boundary requirements:
- model runtime must be local via Ollama
- remote AI providers are out of scope
- prompts must be defensive and evidence-bound
- responses must be parsed into a constrained schema
- invalid or unavailable AI responses must fail closed into warnings or no-op behavior
- AI suggestions must remain advisory only

The AI layer is not an agent loop controller.

## Architectural Implications
The architecture is split into distinct responsibilities:

- scope and target validation define what may be scanned
- the tool registry defines what may be executed
- the orchestrator decides what runs and when
- normalizers convert raw results into structured evidence
- the AI analyzer consumes evidence and emits interpretations
- reporting presents both facts and interpretations with provenance

This means:
- orchestration must not parse AI output into executable actions
- prompts must not advertise command execution capability
- reports must distinguish observations from AI interpretation
- artifacts must preserve execution provenance so AI reasoning can be discounted when source runs are degraded

## Consequences
Positive:
- clearer security boundary between execution and interpretation
- lower chance of accidental agentic drift
- more predictable runtime behavior
- easier auditing and testing
- safer use of local models in professional workflows

Negative:
- the AI cannot dynamically request new tools or scans
- users expecting a fully agentic workflow will see a narrower product
- orchestration changes require code changes rather than prompt changes

## Guardrails for Future Changes
Any future proposal should be rejected or escalated for review if it:
- lets the model select or construct commands
- adds free-form tool execution from AI output
- allows prompts to change runtime execution policy
- introduces web search or external retrieval controlled directly by the model
- treats AI output as equivalent to verified evidence

If future requirements call for AI-directed execution, that requires a new ADR and an explicit redesign of the safety model rather than an incremental extension of the current system.
