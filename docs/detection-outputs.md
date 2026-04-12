# Detection Outputs

Drake-X emits candidate detection artifacts from PE analysis:

- YARA rules (`pe_candidates.yar`)
- STIX 2.1 bundle (`pe_stix.json`)

Both are opt-in via `--detection-output` on `drake pe analyze`.

## Doctrine

Everything Drake-X generates here is **candidate output for analyst
review**. The platform does not ship validated detections:

- YARA rules are generated directly from deterministic evidence
  (carved shellcode, high-entropy sections whose names match known
  packer signatures, injection-chain import combinations). Strings
  are taken verbatim from what the sample actually contains.
- STIX bundles carry hashes of the analyzed sample and indicators
  derived from exploit-indicator heuristics (confidence ≥ 0.5).
  Every indicator is tagged `candidate` and `drake-x-generated`.
- No rule is emitted unless the evidence meets a minimum floor
  (for example, a packer rule requires both a high-entropy executable
  section and a known packer-name hit; an injection-chain rule
  requires at least three imports).

Analysts must tune, corpus-test, and sign off on rules before using
them operationally. Drake-X does not claim false-positive or
false-negative rates for generated rules.

## Reproducibility

Both YARA and STIX outputs are byte-reproducible for identical input:

- **STIX.** All UUIDs (bundle, indicator, relationship) are derived via
  `uuid5(NAMESPACE_OID, ...)` over stable inputs. All STIX timestamp
  fields (`created`, `modified`, `valid_from`, `generated_at`) are
  frozen to the sentinel `1970-01-01T00:00:00+00:00`. The bundle
  carries an `x_drake_x.reproducibility_note` pointing to the
  workspace manifest for the real generation time.
- **YARA.** The `meta.generated_at` field on every candidate rule is
  frozen to the sentinel `1970-01-01`. Real generation time is
  recorded in the workspace manifest; the YARA text stays stable
  across day boundaries and across re-runs.

Downstream consumers that require wall-clock timestamps must read the
workspace manifest and stamp real time at egress rather than trust
the sentinel.

## YARA output

- Rules are named `Drake_Candidate_<category>_<shortsha>_<n>`.
- Each rule's `meta` block includes:
  - `source = "drake-x"`
  - `type = "candidate"`
  - `source_sha256` (full SHA-256 of the sample that generated the rule)
  - `detection_reason` or `indicator`
  - `confidence` (for evidence that had one)
  - `note = "candidate — analyst review required"`
- Conditions are conservative. For example, injection-chain rules
  require three of the API strings to match, not one.

## STIX output

- STIX 2.1 bundle.
- Contains a `file` SDO for the sample (hashes + size) and one
  `indicator` SDO per high-confidence exploit indicator, with
  `relationship` SDOs linking them.
- The bundle carries a top-level `x_drake_x` object containing the
  generator version and an analyst-review caveat.
- The `file` SDO's UUID is derived deterministically from the sample's
  SHA-256 so bundle IDs are stable across re-runs.

## What is intentionally not generated

- Sigma rules are not emitted in v1.0. The writer interface is
  designed to be symmetric with YARA/STIX; a Sigma writer is a
  straightforward addition once a clean source mapping is agreed.
- No network-based IoCs are emitted from PE analysis alone. That
  domain belongs to APK or IoC-session paths.

## CLI

```bash
drake pe analyze sample.exe --detection-output
```

Outputs land in the PE work directory alongside the JSON/Markdown
reports:

```
pe_analysis.json
pe_graph.json
pe_report.md
pe_executive.md
pe_candidates.yar        # only if signals justify it
pe_stix.json             # only if a hash is available
```
