# ADR-0003: Workspace and Scope Model

## Status
Accepted

## Context
ADR-0001 froze Drake-X as a recon assistant rather than an offensive
framework. ADR-0002 nailed down the local-AI / fixed-tool-policy
boundary. As the project grew into a small framework (multi-target
engagements, multiple sessions, optional plugins, AI tasks beyond
single-shot triage), the v0.1 model — one global SQLite file, one
output directory under the repo root, and per-input target safety as
the only "scope" — stopped scaling.

We needed:

- A unit of reproducibility larger than a session.
- An operator-declared engagement scope independent of the per-input
  safety guard.
- An auditable record of every action the engine planned, denied, or
  performed.
- A way for active modules to require operator confirmation without
  baking interactive prompts into every adapter.

## Decision
Drake-X v0.2 introduces three new framework primitives:

1. **Workspace** (`drake_x.core.workspace.Workspace`)
   - One directory per engagement, default
     `~/.drake-x/workspaces/<name>/`.
   - Holds `workspace.toml`, `scope.yaml`, `drake.db`, `runs/`, and
     `audit.log`.
   - Operators may also init a workspace in the current directory with
     `--here`.
   - The unit of reproducibility: copying a workspace directory is
     sufficient to re-render every report on another host.

2. **Scope file** (`drake_x.models.scope.ScopeFile` /
   `drake_x.safety.scope_file`)
   - Operator-declared in/out-of-scope assets.
   - Six asset kinds: `domain`, `wildcard_domain`, `ipv4`, `ipv6`,
     `cidr`, `url_prefix`.
   - Out-of-scope rules win over in-scope rules.
   - `allow_active` defaults to `false`. Active modules are denied
     until the operator flips it AND confirms each run.
   - The scope is snapshotted into the database at the start of every
     session for after-the-fact auditability.
   - Loaded from YAML when PyYAML is available, otherwise from a small
     built-in subset reader. Programmatic snapshots are written as
     JSON for portability.

3. **Audit log** (`drake_x.core.audit.AuditLog`)
   - Append-only JSONL at `<workspace>/audit.log`.
   - Records `plan`, `dry_run`, `confirm`, `run.start`, `run.finish`,
     and explicit `deny` events.
   - Never rewritten or rotated by Drake-X. Treated as evidence.

## Architectural Implications
The engine (`drake_x.core.engine.Engine`) is the new orchestrator.
Compared to v0.1 it adds:

- explicit `plan(target, profile) → EnginePlan` step
- scope enforcement before tool selection (raises `OutOfScopeError`)
- policy classification per integration (passive / light / active /
  intrusive)
- a confirmation gate for active actions
- dry-run support
- audit log writes for every transition

The v1 single-shot orchestrator (`drake_x.orchestrator`) and CLI
(`drake_x.cli._legacy`) are kept verbatim. Both `drake-x` and `drake`
console entry points are registered. The v1 SQLite schema is unchanged;
v2 adds new tables (`scope_assets`, `finding_extras`) additively so a
v0.1 database upgrades in place.

## Consequences
Positive:
- Multi-target engagements are now first-class.
- Scope is a real artifact, not a code constant.
- Active actions cannot escape the audit trail.
- Reproducibility is a `cp -r` of the workspace.
- The legacy CLI keeps working, so v0.1 users see no breakage.

Negative:
- Two CLI surfaces (`drake` and `drake-x`) until the v1 surface is
  deprecated. Manageable as long as both are documented.
- Operators must learn the workspace concept. Mitigated by the
  `drake init` scaffolder and the example files under `examples/`.
- Two storage tables (v1 `findings` + v2 `finding_extras`) for the
  duration of the migration window. The composed `WorkspaceStorage`
  hides this from callers.

## Guardrails for Future Changes
- Never move responsibility for an authorization decision out of the
  safety layer. Every `plan` and `run` step must consult the
  enforcer, the policy classifier, and the confirmation gate.
- Never let an AI task observe the scope file. AI runs only on
  artifacts; authorization context stays out of the prompt.
- Never let the audit log writer raise. It must absorb its own
  errors and warn rather than crash a run.
- Any new "active" integration must add a `policy.py` entry **and** a
  test that exercises the deny path.
