# Drake-X Vision

## Vision

Drake-X is a local-first, evidence-driven malware analysis and threat
investigation platform for Kali Linux. It exists to make authorized
defensive investigations — malware triage, native binary inspection,
indicator-of-compromise enrichment, and analyst-assisted dynamic
validation — more structured, reproducible, and auditable, without
replacing the analyst who is ultimately responsible for every
investigation decision.

The platform combines tool orchestration, strict scope enforcement,
local AI assistance, and evidence-linked reporting into a single
workflow that runs entirely on the analyst's host. It never calls
home, and it deliberately excludes any exploitation, weaponization,
or post-exploitation capability (see ADR-0001 and ADR-0005 for the
explicit non-goals).

## Why Drake-X Exists

Security assessments produce large volumes of tool output, scattered
across terminal sessions, temporary files, and operator memory. Findings
are hard to reproduce, evidence is hard to trace, and reports are
assembled manually long after the assessment is over.

At the same time, operators face a growing set of tools, each with its
own output format, invocation quirks, and false-positive profile. The
temptation to build ad hoc scripts grows with every engagement — and so
does the risk of scope drift, lost evidence, and unreproducible results.

Drake-X addresses these problems directly:

- It provides a **workspace model** that contains everything for one
  engagement: config, scope, database, evidence, and audit log.
- It provides a **scope enforcement layer** that refuses to act on
  targets the operator has not explicitly declared as in-scope.
- It provides **structured normalization** that turns raw tool output
  into artifacts with provenance, confidence, and degraded-execution
  markers.
- It provides a **findings model** that tags every observation with its
  source (rule, AI, parser, operator) and whether it is an observed
  fact or an AI-generated inference.
- It provides a **local AI layer** that can summarize, classify,
  deduplicate, and draft report sections — without sending any data
  off the host.
- It provides **evidence-driven reporting** in five formats, each
  carrying inline links back to the artifacts and tools that produced
  each finding.

## Core Principles

These principles guide every design decision in Drake-X. They are not
aspirational — they are enforced in the codebase today.

**Human-in-the-loop by design.** Drake-X is an assistant, not an
autonomous agent. The operator initializes the workspace, declares the
scope, selects the module, confirms active actions, and validates
findings. The engine plans, executes, normalizes, and reports. It never
decides to scan something the operator did not ask for.

**Strict scope enforcement.** The engagement scope file is the
operator's authoritative declaration of what is in bounds. It must
exist before any tool runs. Out-of-scope rules always win. Targets that
match no in-scope rule are denied by default. Active integrations are
refused unless the scope explicitly permits them, and even then the
operator must confirm each run.

**Local-first AI.** The AI layer communicates only with a local Ollama
instance. There is no remote AI client, no API key field, and no code
path that sends data to any external provider. AI tasks read stored
artifacts. They never invoke tools, never see the scope file, and never
mutate storage directly. Their output is always labeled `inference` to
distinguish it from observed evidence.

**Evidence-centric operations.** Every tool result is normalized into a
structured artifact with provenance (command, exit code, duration,
degraded flag). Every finding carries evidence backrefs, CWE/OWASP/MITRE
classification, confidence, and a fact-vs-inference label. Reports embed
these links so an analyst can trace any claim back to the raw tool output
that produced it.

**Reproducibility and auditability.** The workspace directory is the
unit of reproduction. It contains the operator config, the engagement
scope, the SQLite database of sessions and artifacts, the per-session
evidence exports, and an append-only audit log of every engine event.
Copy the directory to another host and every report can be re-rendered.
The scan manifest records Drake-X version, host platform, Python version,
command lines, exit codes, and a per-tool timeline.

**Modular extensibility.** Integrations, modules, AI tasks, report
writers, and normalizers are independent units. Adding a new tool means
writing one adapter, one normalizer, and one policy entry. Third-party
packages can register integrations via entry points without modifying
the core.

## Product Direction

Drake-X is not a finished product. It is a working framework with a
clear trajectory:

- **Deepen integration coverage.** Promote the remaining tool stubs
  (subfinder, amass, naabu, dnsx, nuclei, feroxbuster, eyewitness,
  testssl) to real implementations with normalizers and evidence
  preservation.
- **Strengthen the findings pipeline.** Add cross-tool correlation,
  automatic CWE/OWASP tagging from rule-based heuristics, and
  confidence calibration based on multi-source agreement.
- **Extend the reporting layer.** Add HTML rendering, PDF export, and
  template customization via Jinja so operators can match their
  organization's report format.
- **Improve the AI task layer.** Add a "watch" mode that diffs
  successive scans and asks the LLM what changed. Add a
  cross-session trend analysis task.
- **Support multi-target engagements natively.** Allow a single
  workspace to manage multiple targets with shared scope and a unified
  findings view.

These directions are planned, not promised. Each one will land only
when its implementation meets the framework's quality and safety
standards.

## Non-Goals

Drake-X does not and will not:

- **Replace the operator.** It assists with triage, normalization, and
  reporting. It does not decide what to scan, when to escalate, or
  whether a finding is real.
- **Perform exploitation.** It does not execute exploits, generate
  payloads, attempt credential attacks, brute force, or post-exploitation
  of any kind. The code and the AI prompts both enforce this boundary.
- **Run autonomously.** There are no agent loops, no automatic
  escalation chains, and no unsupervised scan-then-exploit workflows.
- **Depend on cloud services.** There is no remote AI provider, no
  telemetry, no external API dependency, and no network call that is
  not a direct subprocess of a locally installed tool against an
  in-scope target.
- **Optimize for speed over safety.** Rate limits, confirmation gates,
  and scope checks add latency. That is by design. An unauthorized scan
  that finishes fast is worse than an authorized scan that takes longer.

## Long-Term Outlook

Drake-X aims to become the standard local-first platform for
structured, evidence-driven malware analysis and defensive threat
investigation on Kali Linux. Not by being the fastest triage tool in
the analyst's workflow, but by being the most disciplined: the one
that enforces scope, preserves evidence, separates fact from
inference, and makes every investigation reproducible.

The platform is designed for analysts who take authorization
seriously, who need their reports to hold up under scrutiny, and who
want an AI assistant that helps them think — not one that acts on
their behalf.
