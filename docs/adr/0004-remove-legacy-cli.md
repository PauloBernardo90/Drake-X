# ADR-0004: Remove the legacy `drake-x` CLI

## Status
Accepted

## Context
Drake-X v0.1 shipped a single-shot CLI (`drake-x scan`, `drake-x report`,
`drake-x tools list`) backed by `drake_x/cli.py`. When v0.2 introduced
workspaces, scope enforcement, modules, and the multi-verb `drake` CLI,
the legacy surface was preserved as a backwards-compatible wrapper at
`drake_x/cli/_legacy.py` with its own `drake-x` console entry point.

Maintaining two CLIs created three concrete problems:

1. **User confusion.** Documentation had to qualify every example with
   "use `drake` (recommended) or `drake-x` (legacy)". New users
   installed both binaries and did not know which one to use.
2. **Maintenance drag.** The legacy wrapper imported the v1 orchestrator,
   v1 registry, and v1 session store directly. Changes to shared code
   had to be validated against both entry points.
3. **Product identity.** The project's positioning as a *framework*
   (workspaces, scope, modules, AI tasks, reporting) was undercut by a
   parallel one-shot binary that skipped the engagement model entirely.

No tests exercised the legacy CLI surface. No external tooling was known
to depend on the `drake-x` binary name.

## Decision
Remove the legacy `drake-x` CLI entirely:

- Delete `drake_x/cli/_legacy.py`.
- Remove the `drake-x = "drake_x.cli:app"` console entry point.
- Rename the `app_v2` Typer object to `app` and expose it as the sole
  export from `drake_x.cli`.
- Update `__main__.py` to invoke the same `app`.
- Scrub all documentation of legacy-CLI references, examples, and
  qualifiers.

The underlying v1 modules (`orchestrator.py`, `registry.py`,
`session_store.py`, `reports/markdown.py`, `config.py`) are **not
removed**. They are still the backbone of the v0.3 engine, storage
layer, and reporting pipeline. Only the CLI wrapper that wired them into
the `drake-x scan/report/tools list` verbs is gone.

## Consequences

Positive:
- One binary, one CLI, one set of docs.
- Simpler onboarding for new users.
- No more dual-validation overhead for contributors.
- The `drake` CLI is unambiguously the product surface.

Negative:
- Any user who hard-coded `drake-x` in a shell script will need to
  update it. There was no deprecation warning period because no
  external consumers were identified.
- `python -m drake_x` now invokes the framework CLI (with workspace
  resolution), not the old single-shot CLI. Users who invoked it
  without a workspace will see a "no workspace found" error and must
  run `drake init` first.

## Migration for affected users
- Replace `drake-x scan <target>` with
  `drake init default && drake recon run <target> -m recon_passive -w default`.
- Replace `drake-x report <id>` with `drake report generate <id>`.
- Replace `drake-x tools list` with `drake tools`.

## Guardrails
- The v1 orchestrator, registry, session store, and normalizers remain
  in their current locations and are tested by the original v1 test
  suite. They must not be removed until the v0.3 engine no longer
  delegates to them.
- If a future change adds another CLI surface (e.g. a TUI, a daemon),
  it must be a new module — not a resurrection of `_legacy.py`.
