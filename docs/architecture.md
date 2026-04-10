# Drake-X Architecture

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`safety.md`](safety.md), [`operator-control.md`](operator-control.md)

This document describes how Drake-X is structured, how its components
interact, and how the design principles are enforced in code. It is the
reference for contributors and the source of truth when other documents
disagree.

## Design Principles

- **Human-in-the-loop by design.** The operator declares scope, selects
  modules, confirms active actions, and validates every finding. The
  engine never escalates on its own.
- **Strict scope enforcement.** The engagement scope file is loaded and
  checked before any integration runs. The enforcer, the policy
  classifier, and the confirmation gate each have an independent veto.
- **Evidence over assumptions.** Every finding carries `source` and
  `fact_or_inference`. Rule-based findings are labeled `fact`. AI
  findings are labeled `inference`. The reporting layer renders them
  differently so an analyst never mistakes one for the other.
- **Local-first AI.** The Ollama client is the only LLM transport. There
  is no remote AI client, no API key support, and no telemetry. AI tasks
  read stored artifacts — they never invoke tools or observe the scope
  file.
- **Reproducibility and auditability.** A workspace directory is the
  unit of reproduction. It contains the config, scope, database,
  evidence, and audit log. Copy the directory to another Kali host and
  every report can be re-rendered against the same evidence.

## Layered diagram

```
              ┌──────────────────────┐
              │        CLI           │  drake init / scope / recon / web /
              │   drake_x.cli       │  api / findings / ai / report / tools
              └─────────┬────────────┘
                        ▼
              ┌──────────────────────┐
              │     Workspace        │  ~/.drake-x/workspaces/<name>/
              │ drake_x.core.        │   ├ workspace.toml
              │   workspace          │   ├ scope.yaml
              └─────────┬────────────┘   ├ drake.db
                        │                ├ runs/<session>/
                        │                └ audit.log
                        ▼
       ┌──────────────────────────────────┐
       │            Engine                │  plan → scope check → policy
       │     drake_x.core.engine          │  → confirm → run → normalize
       └──┬─────────┬──────────┬──────────┘  → findings → persist → audit
          │         │          │
          ▼         ▼          ▼
   ┌─────────┐ ┌────────┐ ┌──────────────┐
   │ Plugin  │ │ Safety │ │  Modules     │
   │ loader  │ │ layer  │ │  (recon,     │
   │         │ │        │ │   web, tls,  │
   │         │ │        │ │   headers,   │
   │         │ │        │ │   content,   │
   │         │ │        │ │   api)       │
   └────┬────┘ └────────┘ └──────┬───────┘
        │                        │
        ▼                        ▼
   ┌───────────────┐      ┌─────────────────┐
   │ Integrations  │      │  Normalizers    │
   │ (subprocess   │─────►│  → Artifact     │
   │  wrappers)    │      │  → Headers audit│
   └───────────────┘      │  → Findings     │
                          └────────┬────────┘
                                   │
                                   ▼
                          ┌─────────────────┐
                          │   Storage       │
                          │  (SQLite)       │
                          └────────┬────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
       ┌────────────┐       ┌────────────┐       ┌────────────┐
       │  AI tasks  │◄──────│  Findings  │──────►│  Reporting │
       │  (Ollama)  │       │  (rule +   │       │  md / json │
       │            │       │   AI +     │       │  executive │
       │            │       │   operator)│       │  manifest  │
       └────────────┘       └────────────┘       │  diff      │
                                                 └────────────┘
```

## Major building blocks

### CLI (`drake_x/cli/`)

The `drake` binary is a Typer application with subcommands: `init`,
`scope`, `recon`, `web`, `api`, `findings`, `ai`, `report`, `tools`.
Each subcommand lives in its own module. The CLI resolves the workspace,
loads the scope, builds the engine, and invokes it. It never runs tools
directly.

### Engine (`drake_x/core/engine.py`)

The engine is the central orchestrator. A single `run()` invocation:

1. Resolves the workspace and loads the engagement scope.
2. Validates the target via `drake_x.scope.parse_target()` (rejects
   loopback, link-local, huge CIDRs — independent of any scope file).
3. Calls `ScopeEnforcer.check_target()` against the scope file. Raises
   `OutOfScopeError` if denied.
4. Builds a plan: selects integrations for the chosen profile, classifies
   each by policy, identifies which require operator confirmation.
5. Passes active integrations through `ConfirmGate.require()`.
6. Executes eligible integrations (parallel-safe ones concurrently,
   serial ones sequentially). HTTP-style integrations are gated by the
   `RateLimiter`.
7. Normalizes each `ToolResult` into an `Artifact`.
8. Runs the security headers audit (rule-based findings).
9. Optionally runs the AI analyzer (findings labeled `inference`).
10. Persists session, tool results, artifacts, findings, and scope
    snapshot.
11. Writes a `run.finish` event to the audit log.

If anything raises, the engine writes a deny or error event to the audit
log before propagating.

### Workspace model (`drake_x/core/workspace.py`)

A workspace is a directory containing everything for one engagement:

```
~/.drake-x/workspaces/<name>/
  workspace.toml          operator config (AI model, timeout, module)
  scope.yaml              engagement scope (in/out assets, rate limits)
  drake.db                SQLite database (sessions, results, artifacts, findings)
  runs/<session-id>/      per-session reports and evidence exports
  audit.log               append-only JSONL of every engine event
```

The workspace is the unit of reproducibility. Copying it to another host
is sufficient to re-render every report and re-run every AI task against
the same evidence.

### Scope enforcement (`drake_x/safety/`)

Four independent layers, evaluated in order:

1. **Target validation** (`scope.py`) — rejects unsafe inputs regardless
   of the scope file.
2. **Engagement scope** (`safety/enforcer.py`) — matches the target
   against the operator-declared `in_scope` and `out_of_scope` rules.
   Out-of-scope always wins. No match means deny.
3. **Action policy** (`safety/policy.py`) — classifies each integration
   as passive, light, active, or intrusive. Active and intrusive require
   `scope.allow_active=true`.
4. **Confirmation gate** (`safety/confirm.py`) — prompts the operator
   before executing active or intrusive integrations. `--dry-run` plans
   without executing. `--yes` pre-approves. Non-TTY sessions are refused.

### Audit logging (`drake_x/core/audit.py`)

Every plan, run, denial, confirmation, dry-run, and completion event is
appended as one JSON line to `<workspace>/audit.log`. The audit log is
append-only by convention. Drake-X never rewrites or rotates it.

### Integrations (`drake_x/tools/`, `drake_x/integrations/`)

Each integration is a `BaseTool` subclass that declares metadata
(`ToolMeta`), builds a safe argv list, and is executed via
`asyncio.create_subprocess_exec`. No shell strings are ever constructed.
Output is captured, truncated, and stored as a `ToolResult`.

Integrations opt into the rate limiter via `ToolMeta.http_style=True`.
The plugin loader discovers built-in adapters, real optional integrations
(httpx, ffuf), and third-party packages registered through the
`drake_x.integrations` entry-point group.

### AI task layer (`drake_x/ai/tasks/`)

Each AI task is a small class with a name, a file-based prompt template
(under `prompts/`), a JSON schema the model must satisfy, and a
deterministic temperature setting. Tasks read stored artifacts and
findings. They never invoke tools, never see the scope file, and never
mutate storage directly. Their output is wrapped as
`Finding(source=AI, fact_or_inference="inference")`.

Implemented tasks: `summarize`, `classify`, `next_steps`, `observations`,
`report_draft`, `dedupe`.

### Reporting pipeline (`drake_x/reporting/`)

Five independent writers, each producing one output format:

- **Technical Markdown** — findings table with severity sort, CWE/OWASP
  badges, inline evidence links, timeline, fact vs inference labels.
- **Executive Markdown** — short, non-technical summary for stakeholders.
- **JSON** — canonical machine-readable report for CI and downstream
  tooling.
- **Manifest** — command lines, exit codes, durations, host info, and
  timeline for reproducibility.
- **Evidence index** — Markdown table mapping each artifact to its tool,
  confidence, and degraded status.

Session-to-session diff (`drake_x/normalize/diff.py`) compares artifacts
from two sessions and produces added/removed/changed entries for
tracking attack-surface changes over time.

### Findings and evidence model (`drake_x/models/finding.py`)

Every finding carries:

- `source`: `rule`, `ai`, `parser`, or `operator`
- `fact_or_inference`: `fact` (deterministic, observed) or `inference`
  (AI-generated, probabilistic)
- `evidence`: list of `FindingEvidence` backrefs pointing at the
  artifact kind and tool that produced the observation
- `cwe`, `owasp`, `mitre_attck`: optional classification references
- `confidence`: 0.0 to 1.0
- `remediation`: placeholder text for report drafts
- `tags`: operator-applied labels (e.g. `triaged`, `false-positive`,
  `duplicate-of:<id>`)

## How fact vs inference is handled

1. Normalizers produce `Artifact` objects. These are raw observations.
2. The headers audit produces `Finding(source=RULE, fact_or_inference="fact")`.
   The absence of a security header is a fact.
3. The AI layer produces `Finding(source=AI, fact_or_inference="inference")`.
   The model's classification or summary is interpretation.
4. Every report format renders the source and fact/inference flag inline.
5. AI tasks never see the scope file. Authorization metadata stays out
   of prompts.

## How reproducibility is achieved

1. The workspace directory is the unit of reproduction.
2. `workspace.toml` records the operator, AI model, and engine defaults.
3. `scope.yaml` records the engagement scope. The scope is snapshotted
   into `scope_assets` at the start of every session.
4. `drake.db` stores every session, tool result, artifact, and finding.
5. `runs/<session-id>/` holds exported reports and evidence.
6. `audit.log` records every engine event with timestamps.
7. The scan manifest includes Drake-X version, host platform, command
   lines, exit codes, and a per-tool timeline.

## How human-in-the-loop operation is enforced

1. `drake init` requires the operator to set up a workspace and edit
   the scope file before any tool runs.
2. `scope.allow_active` defaults to `false`. The operator must
   explicitly enable it.
3. Active and intrusive integrations pass through `ConfirmGate`. `--yes`
   is an explicit opt-in. Non-TTY sessions are refused by default.
4. `--dry-run` lets the operator inspect the plan without executing.
5. Every finding requires analyst validation. Reports state this.
6. AI tasks produce `inference`-labeled findings. The operator decides
   whether to act on them.

## Storage schema

The storage layer composes two schema generations:

- **Base tables** (`sessions`, `tool_results`, `artifacts`, `findings`)
  provide the session/result/artifact/finding foundation.
- **Extended tables** (`scope_assets`, `finding_extras`) add the scope
  snapshot and the full finding model (CWE, OWASP, MITRE, evidence,
  tags, fact_or_inference, remediation).

The extended schema is created with `CREATE TABLE IF NOT EXISTS` and
never alters the base tables.

## Extending the framework

- **New integration.** Subclass `BaseTool`, set `ToolMeta`, implement
  `build_command`, add a normalizer, add a policy entry.
- **New module.** Subclass `Module`, set `ModuleSpec`, append to
  `ALL_MODULES`.
- **New AI task.** Add a prompt template to `prompts/`, subclass
  `AITask`, register in `ALL_TASKS`.
- **Third-party plugin.** Register a `drake_x.integrations` entry point
  pointing at a `BaseTool` subclass.
