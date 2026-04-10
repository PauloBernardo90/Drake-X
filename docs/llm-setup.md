# Local LLM setup

See also: [`README.md`](README.md), [`cheat-sheet.md`](cheat-sheet.md),
[`kali-setup.md`](kali-setup.md), [`usage.md`](usage.md)

Drake-X's AI layer is **local-only**. There is no remote AI client in
the code, no API key support, and no telemetry. The optional LLM runs
on the same Kali host via [Ollama](https://ollama.com/).

## Why local-only

- **Engagement data never leaves the box.** Recon output frequently
  contains identifiers, internal hostnames, and customer-sensitive
  metadata. Sending it to a remote provider is rarely an option.
- **Reproducibility.** A workspace directory + an Ollama model name is
  enough to re-run an analysis.
- **Defense in depth.** The model can suggest things, but it cannot
  exfiltrate them.

## 1. Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Start the daemon (it listens on `http://127.0.0.1:11434` by default):

```bash
ollama serve &
```

## 2. Pull a small model

Drake-X defaults to `llama3.2:1b`, which is fast on commodity hardware
and good enough for triage. Pull it:

```bash
ollama pull llama3.2:1b
```

If you have more RAM/VRAM available, `llama3.2:3b` is noticeably
better at the classification task:

```bash
ollama pull llama3.2:3b
```

## 3. Tell Drake-X about it

The model name is per-workspace. Edit the `[ai]` section of
`<workspace>/workspace.toml`:

```toml
[ai]
ollama_url = "http://127.0.0.1:11434"
ollama_model = "llama3.2:3b"
```

Then verify:

```bash
drake ai status -w my-engagement
```

You should see:

```
✓  Ollama reachable at http://127.0.0.1:11434 (model llama3.2:3b)
```

## 4. Run an AI task

AI tasks read existing artifacts and findings from the workspace
database. They never invoke tools themselves. Run them after a recon
session:

```bash
drake recon run example.com -m recon_passive -w my-engagement
# capture the session id from the output, then:
drake ai summarize     <session-id> -w my-engagement
drake ai classify      <session-id> -w my-engagement
drake ai next-steps    <session-id> -w my-engagement
drake ai observations  <session-id> -w my-engagement
drake ai draft-report  <session-id> -w my-engagement
```

Each task prints a single JSON object. Ill-formed responses are
ignored — Drake-X never tries to "fix" model output by silently
inventing fields.

## 5. Customizing prompts

The prompts live as plain Markdown under `prompts/` at the repo root:

```
prompts/
  system_analyst.md      # system prompt prepended to every task
  task_summarize.md      # SummarizeTask
  task_classify.md       # ClassifyTask
  task_next_steps.md     # NextStepsTask
  task_dedupe.md         # DedupeTask (registered, no command yet)
  task_report_draft.md   # ReportDraftTask
```

Edit them in place. The task classes load them on every call, so
there's no rebuild step.

If you customize a prompt:

- **Keep the JSON-only output rule.** Drake-X parses one JSON object
  out of the response and discards anything else. Removing the schema
  block will likely break the parser.
- **Keep the defensive constraints.** The system prompt forbids
  exploitation suggestions. Removing those constraints would not turn
  Drake-X into an exploit framework (the engine still refuses), but
  it would leak garbage findings into your reports.
- **Keep the placeholders.** Each template is interpolated with
  `{target_display}`, `{profile}`, `{evidence_json}`, `{findings_json}`,
  `{schema_json}`, etc. Removing a placeholder will raise a `KeyError`
  at run time.

## 6. Failure modes

| Symptom                                  | Likely cause                          | Fix                                                                  |
|------------------------------------------|---------------------------------------|----------------------------------------------------------------------|
| `Ollama NOT reachable`                   | daemon not running                    | `ollama serve &`                                                     |
| `model 'llama3.2:1b' not found`          | model not pulled                      | `ollama pull llama3.2:1b`                                            |
| AI task returns `model response was not valid JSON` | model rambling     | try a larger model or simplify the evidence with `--limit-evidence` |
| AI task says no findings                 | not enough evidence                   | run a longer recon profile first                                     |

## 7. What the AI never does

- It does not invoke tools.
- It does not see the engagement scope file.
- It does not produce exploit, payload, or post-exploitation content.
- It does not change findings without going through the storage layer
  (so its output is auditable like any other finding).
- It does not run unless the operator passed `--ai` (or, in v0.1
  legacy mode, did not pass `--no-ai`).
