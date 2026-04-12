# Reporting

Drake-X v1.0 has two reporting layers: per-session reporting and
case-level aggregation.

## Per-Session Reports

Existing report formats remain:

- technical Markdown
- executive Markdown
- JSON
- manifest
- evidence index
- session diff between two sessions

CLI:

```bash
drake report generate <session-id> -f md -w my-engagement
drake report generate <session-id> -f executive -w my-engagement
drake report generate <session-id> -f json -w my-engagement
drake report generate <session-id> -f manifest -w my-engagement
drake report diff <session-a> <session-b> -w my-engagement
```

## Case Report

v1.0 adds:

```bash
drake report case -w my-engagement
drake report case -w my-engagement --format json
drake report case -w my-engagement -o case_report.md
```

The case report aggregates:

- session index
- dominant domain per session
- node and edge counts
- cross-session correlations
- persisted validation plans

It is a workspace-level view. Specialized PE/APK/ELF reports remain the
authoritative per-session documents.

## Candidate Detection Outputs

PE analysis can also emit candidate detection artifacts:

- `pe_candidates.yar`
- `pe_stix.json`

These are candidate outputs for analyst review, not validated
detections.

## Evidence vs Inference

Reporting surfaces are expected to preserve:

- deterministic evidence
- analytic assessment
- imported external evidence
- AI-backed inference
- analyst recommendation / validation hypothesis

The reporting layer should never flatten those categories into one
undifferentiated conclusion stream.
