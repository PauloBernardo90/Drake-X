# Drake-X Console Persistent Analysis Requirements

Requirements for a persistent investigation console in Drake-X.

- Date: 2026-04-11
- Scope: Post-v0.8 CLI UX evolution
- Status: Draft requirements

## 1. Objective

Introduce a persistent console for Drake-X so analysts can stay inside a
single investigation context instead of repeatedly invoking stateless
one-shot commands.

The console must support:

- persistent workspace context
- persistent session context
- evidence-guided investigation workflows
- reduced visual noise
- command reuse without repeating `--workspace` and `session_id`

This is conceptually similar to a console-oriented workflow such as
Metasploit, but adapted to Drake-X's evidence-driven malware analysis
model rather than offensive operations.

## 2. Product Intent

The console exists to improve analyst productivity, continuity, and
context retention.

It is not intended to:

- create an exploit-operations shell
- replace external debuggers
- introduce persistent offensive runtime control

The Drake-X console is a persistent analysis shell, not an operator
console for exploitation.

## 3. Current Constraints in Drake-X

The current CLI already provides:

- workspace persistence through `workspace.toml`
- session persistence through SQLite-backed session storage
- report, AI, graph, and findings commands that work on stored sessions
- a startup banner rendered through the global CLI callback

The current pain points are:

- the banner is printed on every command invocation
- operators repeatedly pass `-w <workspace>`
- operators repeatedly pass `session_id`
- related analysis tasks are spread across separate shell invocations

## 4. High-Level Design

Drake-X should gain a dedicated entry point:

- `drake console`

This console should:

- render the banner once at startup
- load or create investigation context
- expose a prompt with current context
- dispatch to existing Drake-X commands
- persist current workspace and session state between console launches

## 5. Functional Requirements

### R1. Persistent Console Entry Point

The platform must provide:

- `drake console`

This command must:

- open an interactive REPL
- remain active until the operator exits
- print the brand/banner once per console session

### R2. Persistent Workspace Context

The console must track an active workspace.

Required behaviors:

- show the active workspace in the prompt
- allow switching workspaces
- allow creating a new workspace from inside the console
- use the active workspace by default for subsequent commands

Minimum commands:

- `workspace list`
- `workspace use <name>`
- `workspace show`
- `workspace new <name>`

### R3. Persistent Session Context

The console must track an active analysis session.

Required behaviors:

- list prior sessions in the current workspace
- select a session as current
- display current session metadata
- use the current session by default for session-oriented commands

Minimum commands:

- `session list`
- `session use <session-id>`
- `session show`

### R4. Context-Aware Command Dispatch

Within the console, Drake-X must allow command execution without
repeating context already selected in the session.

Examples:

- `apk analyze /path/sample.apk`
- `ai summarize`
- `report executive`
- `findings list`
- `graph show`

The console should supply:

- current workspace automatically
- current session automatically where required

Explicit user arguments must always override implicit context.

### R5. Prompt Design

The prompt must communicate active investigation context clearly.

Recommended prompt forms:

- `drake(my-engagement)>`
- `drake(my-engagement:376431952b79)>`

The prompt must update immediately when workspace or session changes.

### R6. Banner Strategy

The banner must no longer be shown on every one-shot command by default.

Required behavior:

- show banner on `drake console`
- allow compact header on narrow terminals
- suppress banner in machine-readable or piped output
- avoid re-rendering branding during every subcommand inside the console

### R7. Terminal-Aware Branding

Brand rendering must adapt to terminal width.

The implementation must support at least three display modes:

- large banner
- medium banner
- compact header

The active mode must be selected using measured terminal width at
runtime.

### R8. Console State Persistence

Drake-X must persist lightweight console context outside the session DB.

Recommended location:

- `~/.drake-x/state.json`

Minimum state fields:

- `current_workspace`
- `current_session`
- `last_sample_path`
- `last_run_dir`

This state must be:

- safe to delete
- small
- non-authoritative compared with workspace/session artifacts

### R9. Backward Compatibility

All current non-console commands must continue to work exactly as they do
today.

The console is an additive UX layer, not a replacement for the existing
CLI.

### R10. Help and Discoverability

The console must expose built-in guidance for:

- listing commands
- showing current context
- exiting cleanly

Minimum commands:

- `help`
- `status`
- `tools`
- `exit`

## 6. Technical Requirements

### T1. State Layer

Introduce a lightweight state module, for example:

- `drake_x/core/state.py`

Responsibilities:

- load/save current console state
- expose getters/setters for active workspace/session
- degrade gracefully if state file is missing or invalid

### T2. Console Command Module

Introduce:

- `drake_x/cli/console_cmd.py`

Responsibilities:

- REPL loop
- prompt rendering
- command dispatch
- context updates
- command parsing for internal console verbs

### T3. Shared Context Resolution

Update shared workspace/session resolution logic so that precedence
becomes:

1. explicit CLI argument
2. console state
3. environment variable
4. current-directory workspace
5. default workspace

### T4. Reuse Existing Commands

The console should reuse existing Drake-X command implementations where
possible.

It must not duplicate business logic already implemented in:

- analysis commands
- findings commands
- graph commands
- report commands
- AI commands

### T5. Bounded Scope

The console must not introduce:

- debugger-like interaction inside Drake-X
- persistent runtime manipulation
- exploit-operational UX

## 7. Terminal Size Requirements

The Kali terminal size must be measurable at runtime so banner logic can
adapt reliably.

Measurement methods to support during validation:

- `stty size`
- `tput cols`
- `tput lines`
- Python `shutil.get_terminal_size()`

The implementation should use runtime terminal width, not hardcoded
assumptions tied to a single environment.

## 8. Minimum Viable Console

The first implementation should include:

- `drake console`
- one-time banner render
- persistent workspace state
- persistent session state
- prompt with current context
- commands:
  - `workspace list`
  - `workspace use <name>`
  - `workspace show`
  - `session list`
  - `session use <id>`
  - `session show`
  - `status`
  - `tools`
  - `ai summarize`
  - `report executive`
  - `findings list`
  - `graph show`
  - `exit`

## 9. Validation Requirements

The implementation must be validated against:

- workspace switching
- session switching
- command execution without repeating `-w`
- command execution without repeating `session_id`
- state persistence across console restarts
- banner appearing once per console session
- banner adapting to terminal width
- one-shot CLI behavior remaining intact

## 10. Anti-Goals

The console must not become:

- an exploit shell
- a debugger replacement
- an autonomous runtime analysis controller
- a shellcode execution interface
- a long-running offensive operator console

## 11. Definition of Done

This requirement set is satisfied when:

- an analyst can launch `drake console`
- set or switch workspace once
- set or switch session once
- run multiple analysis/review/reporting commands without repeating
  context
- observe banner/branding only once per console session
- resume work later with prior context restored

## 12. Recommended Implementation Order

1. terminal width validation and banner strategy
2. `core/state.py`
3. shared context resolution updates
4. `cli/console_cmd.py`
5. workspace commands
6. session commands
7. command dispatch to existing CLI logic
8. tests
9. docs
