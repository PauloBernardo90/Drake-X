# Drake-X Safety Model

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`architecture.md`](architecture.md), [`usage.md`](usage.md)

Safety in Drake-X is not a feature bolted on after the fact. It is a
core architectural property. For v0.7, that means two things at once:
target-facing collection workflows remain tightly scoped and controlled,
and local sample-analysis workflows remain evidence-preserving,
auditable, and non-weaponizing.

Read this document before running Drake-X against any target or sample.
Re-read it any time you modify `scope.yaml`, enable active recon, or
introduce new malware-analysis tooling.

## Design Principles

- **Human-in-the-loop by design.** The operator declares scope, selects
  modules, confirms active actions, and validates every finding. Drake-X
  never escalates autonomously.
- **Strict operator control.** The engagement scope file must exist
  before any target-facing tool runs. Targets outside scope are refused.
  There is no flag to override this.
- **Evidence over assumptions.** Findings produced by deterministic
  rules are labeled `fact`. Findings produced by the AI are labeled
  `inference`. Reports always show which is which.
- **Local-first AI.** AI tasks read stored artifacts only. They never
  invoke tools, never see the scope file, and never send data to a
  remote provider.
- **Reproducibility and auditability.** Every engine event — plan, run,
  deny, confirm, finish — is recorded in the append-only audit log.
  The engagement scope is snapshotted into the database at the start of
  every session.

## Authorization-first workflow

Drake-X enforces an authorization-first workflow for network-facing
collection:

1. The operator runs `drake init` to create a workspace.
2. The operator edits `scope.yaml` to declare the engagement scope,
   including the `authorization_reference` field (PO number, signed
   letter, HackerOne report ID).
3. The operator runs `drake scope validate` to confirm the scope file
   is well-formed.
4. The operator runs `drake scope check <target>` to verify that a
   target falls within scope before scanning.
5. Only then does `drake recon run` accept the target.

No tool executes before the scope is loaded and the target is matched.
Purely local sample analysis does not require network target scope, but
it still inherits the same non-weaponization, auditability, and
human-in-the-loop constraints.

## Enforcement layers

Drake-X evaluates four independent layers in order for target-facing
collection. If any layer says no, the engine never reaches the
integration.

```
┌──────────────────────┐  drake_x/scope.py
│  Target validation   │  rejects loopback, link-local, multicast,
│  (per-input)         │  reserved ranges, and excessively broad CIDRs
└──────────┬───────────┘  regardless of scope file or CLI flags
           ▼
┌──────────────────────┐  drake_x/safety/enforcer.py
│  Engagement scope    │  operator-declared in/out-of-scope assets
│  (per-engagement)    │  out_of_scope always wins; no match = deny
└──────────┬───────────┘
           ▼
┌──────────────────────┐  drake_x/safety/policy.py
│  Action policy       │  every integration is classified:
│  (per-integration)   │  passive / light / active / intrusive
└──────────┬───────────┘
           ▼
┌──────────────────────┐  drake_x/safety/confirm.py
│  Confirmation gate   │  active + intrusive require operator approval
│  (per-active-call)   │  unless --yes or --dry-run is in effect
└──────────────────────┘
```

### Layer 1: target validation

Every target string the operator passes to `drake recon run` goes
through `drake_x.scope.parse_target()` first. This rejects:

- Loopback, unspecified, multicast, link-local, and reserved IP
  addresses
- `localhost` and other single-label hostnames
- IPv4 CIDRs broader than `/22` (approximately 1024 addresses)
- IPv6 CIDRs broader than `/120`
- Non-HTTP(S) URL schemes
- Inputs that do not parse as IP, CIDR, domain, or URL

These rules cannot be overridden via the scope file or CLI flags. They
are the first-line defense against operator typos and misconfigured
automation.

### Layer 2: engagement scope file

The scope file (`<workspace>/scope.yaml`) is the operator's declaration
of what this engagement covers. Drake-X refuses to act on any target
that does not match an `in_scope` rule.

Supported asset kinds:

| `kind`              | Matches                                               |
|---------------------|-------------------------------------------------------|
| `domain`            | Exact host (`api.example.com`)                        |
| `wildcard_domain`   | `example.com` and any subdomain `*.example.com`       |
| `ipv4` / `ipv6`     | Exact address                                         |
| `cidr`              | Any host inside the CIDR                              |
| `url_prefix`        | URL with same scheme/host and a matching path prefix  |

Evaluation order:

1. Check every `out_of_scope` rule. Any match: **DENY**.
2. Check every `in_scope` rule. First match: **ALLOW**.
3. No match: **DENY**.

Out-of-scope rules always win. This lets the operator carve a single
internal host out of a wildcard match without restructuring the file.

The scope is snapshotted into the SQLite database at the start of every
session. Post-mortem analysis can prove which rules were in effect when
a target was assessed.

### Layer 3: action policy

Each integration is classified by `drake_x/safety/policy.py`:

| Policy       | Examples                              | Behavior                                                      |
|--------------|---------------------------------------|---------------------------------------------------------------|
| `passive`    | whois                                 | Always permitted                                              |
| `light`      | dig, curl, sslscan, httpx             | Always permitted, logged                                      |
| `active`     | nmap, whatweb                         | Requires `scope.allow_active=true` AND operator confirmation  |
| `intrusive`  | nikto, ffuf, nuclei, feroxbuster      | Requires `scope.allow_active=true` AND operator confirmation  |

`scope.allow_active` defaults to `false`. Active and intrusive
integrations are denied at the policy layer until the operator
explicitly enables it in `scope.yaml`.

### Layer 4: confirmation gate

Active and intrusive integrations always pass through `ConfirmGate`.
The gate has three modes:

- **interactive** (default) — prompts on stdin per active integration
- **yes** (`--yes`) — pre-approved; still logged
- **deny** (used by `drake recon plan`) — refuses every active call

If Drake-X runs non-interactively (CI, cron) without `--yes`, the gate
refuses the call rather than blocking. This prevents unintended active
recon in automated pipelines.

## Controlled execution

HTTP-style integrations (curl, whatweb, nikto, httpx, ffuf) are gated
by the `RateLimiter`, which enforces:

- **Per-host pacing** — configurable via `scope.rate_limit_per_host_rps`
  (default: 5.0 requests per second per host).
- **Global concurrency budget** — configurable via `scope.max_concurrency`
  (default: 4 concurrent HTTP-style integrations).

Non-HTTP integrations (nmap, dig, whois) bypass the rate limiter
entirely. The limits are enforced in the engine, not in the individual
integrations, so they cannot be circumvented by a custom adapter.

## Fact vs inference separation

Drake-X maintains a strict boundary between observed evidence and
AI-generated interpretation:

- **Normalizers** produce `Artifact` objects. These are structured
  representations of raw tool output. They carry a `confidence` value
  and a `degraded` flag when the underlying tool did not exit cleanly.
- **Rule-based findings** (e.g. from the security headers audit) are
  tagged `source=rule, fact_or_inference=fact`. The absence of a
  security header is an observed fact, not an interpretation.
- **AI findings** are tagged `source=ai, fact_or_inference=inference`.
  The model's summary, classification, or recommendation is
  interpretation, not evidence.
- **Every report format** renders the source and fact/inference flag
  inline. Technical Markdown shows CWE/OWASP badges on each finding
  row alongside the label. JSON reports carry the fields as structured
  data for downstream tooling.
- **AI tasks never see the scope file.** Authorization metadata stays
  out of prompts.

For v0.7, the reporting model expands this into four explicit evidence
classes:

- `fact` — observed parser/tool output
- `inference` — analytic or AI-backed interpretation
- `external_intel` — supplementary read-only enrichment such as
  VirusTotal
- `hypothesis` — dynamic-validation targets that require analyst
  confirmation in a controlled environment

## Audit log

Every engine event is appended as one JSON line to
`<workspace>/audit.log`:

```json
{
  "ts": "2026-04-10T09:12:33+00:00",
  "actor": "operator",
  "action": "run.finish",
  "subject": "api.example.com",
  "decision": "allow",
  "dry_run": false,
  "workspace": "acme-bug-bounty",
  "session_id": "7a4b9e21c133",
  "payload": {"status": "completed", "tools_ran": ["dig", "whois", "curl"]}
}
```

The audit log is append-only by convention. Drake-X never rewrites or
rotates it. Treat it as engagement evidence. If you need to archive old
entries, copy the file — do not truncate the live one mid-engagement.

## Hard refusals

Even with the most permissive scope file and `--yes`, Drake-X will not:

- Run an integration that is not in its registry
- Run an integration that does not support the target type
- Relax per-input target validation
- Emit findings that resemble exploit suggestions (the nikto parser
  suppresses such lines; the AI system prompt forbids them)
- Communicate with a remote AI provider (there is no remote AI client
  in the code)
- Upload malware samples automatically to external services
- Auto-bypass protections during dynamic analysis
- Write outside the workspace directory unless `-o` explicitly points
  elsewhere

## Operator checklist

Before each engagement:

- [ ] Verify the engagement authorization in writing.
- [ ] `drake init <name>` a fresh workspace.
- [ ] Edit `scope.yaml`: set `authorization_reference`, add every
      in-scope asset, add every known out-of-scope carve-out.
- [ ] Decide whether `allow_active` should be `true`. If unsure, leave
      it `false`.
- [ ] `drake scope validate -w <name>` and review the output.
- [ ] `drake scope check <target> -w <name>` for every target you intend
      to assess.
- [ ] `drake recon plan <target> -m <module> -w <name>` to review the
      plan before executing.
- [ ] Run the plan. Read the audit log before escalating to active recon.

When in doubt, deny.
