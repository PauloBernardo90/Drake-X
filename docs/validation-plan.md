# Validation Plan

Drake-X v1.0 introduces a persistent, structured validation plan model
for multi-domain investigations.

## Purpose

A validation plan is an analyst checklist derived from persisted graph
evidence. It is not an executable playbook and it is not a command
queue.

Each item answers:

- what hypothesis should be checked
- why it is plausible
- what evidence is expected
- what tool type may help
- which graph nodes justify the item

## CLI

```bash
drake validate plan <session-id> -w my-engagement
drake validate show <session-id> -w my-engagement
drake validate show <session-id> -w my-engagement --format json
drake validate export <session-id> -w my-engagement -o validation_plan.md
```

## Current Sources

The v1.0 planner currently emits items from:

- PE exploit indicators
- PE suspected shellcode artifacts
- PE protection-interaction assessments
- imported external findings with trust `medium` or `high`

The planner is additive. New domains can extend it without changing the
storage contract.

## Persistence

Plans are stored in SQLite in the `validation_plans` table and keyed by
session ID.

## Boundaries

- Drake-X does not auto-execute plan items
- imported findings remain imported evidence, not confirmed truth
- validation items are hypotheses pending analyst confirmation
