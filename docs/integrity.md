# Integrity, Provenance & Chain of Custody

## Core Principle

> **No evidence exists without a hash. No result exists without a
> reference to the original hash.**

Every sample, artifact, and report in Drake-X is tracked by SHA-256
with a complete chain of custody linking each artifact to the original
sample and the analysis run that produced it.

## Why This Layer Exists

Academic malware research demands:

1. **Reproducibility** — given the same sample, the analysis should
   produce equivalent results
2. **Auditability** — every step from ingest to report is logged
3. **Integrity** — if an artifact is tampered with, verification fails
4. **Provenance** — every finding traces back to a specific sample hash
5. **Chain of custody** — the history of what happened to the sample
   during analysis is preserved

## What Gets Hashed

| Artifact | Hashes | When |
|----------|--------|------|
| Original sample | MD5, SHA-1, SHA-256 | Before any processing |
| Staged copy | SHA-256 | After copying to workspace |
| Extracted DEX files | SHA-256 | After extraction |
| Analysis JSON report | SHA-256 | After generation |
| Markdown report | SHA-256 | After generation |
| Integrity report itself | SHA-256 | Self-hash at generation time |

**SHA-256 is the primary identifier** throughout. MD5 and SHA-1 are
included for compatibility with VirusTotal, YARA, and external feeds.

## Run ID

Every analysis execution gets a unique `run_id` (e.g., `run-a1b2c3d4e5f6`).

- 1 execution = 1 run_id
- All events, artifacts, and reports reference this ID
- Never reused between executions
- Format: `run-` + 12-char hex from UUID v4

## Chain of Custody

The custody chain is an append-only, chronologically ordered log of
events during analysis:

```json
{
  "timestamp": "2025-01-15T10:30:00+00:00",
  "run_id": "run-a1b2c3d4e5f6",
  "action": "ingest",
  "artifact_sha256": "deadbeef...",
  "actor": "apk_cmd",
  "details": "Ingested sample.apk",
  "status": "ok"
}
```

### Tracked Actions

| Action | Description |
|--------|-------------|
| `ingest` | Sample accepted into analysis |
| `stage` | Sample copied to workspace |
| `unpack` | APK/archive unpacked |
| `dex_extract` | DEX files extracted |
| `analyze` | Analysis phase completed |
| `report_generate` | Report created |
| `artifact_register` | Artifact recorded with hash |
| `verify` | Integrity check performed |
| `fail` | Something went wrong |
| `export` | Output exported |

## Versioning

Every analysis records a version snapshot:

```json
{
  "drake_x_version": "1.0.0",
  "pipeline_version": "1.0.0",
  "analysis_profile": "apk_analyze",
  "python_version": "3.13.3",
  "tools": [
    {"tool_name": "apktool", "version": "2.9.3", "availability": "available"},
    {"tool_name": "jadx", "availability": "unavailable", "notes": "not in PATH"},
    {"tool_name": "androguard", "version": "3.4.0", "availability": "available"}
  ]
}
```

If a tool is unavailable, this is **recorded explicitly** — never silently
omitted.

## Integrity Verification

The verifier checks:

1. **run_id present** on report and all events
2. **sample_identity.sha256** matches report.sample_sha256
3. **Artifact hashes** match recorded values (if files still exist)
4. **Artifact run_id and parent_sha256** are consistent
5. **Custody chain** contains required INGEST event
6. **Custody events** are in chronological order
7. **Report hash** is valid if present

### Fail-Closed

If **any** check fails, the verifier raises `IntegrityVerificationError`
and processing stops. There is no "warn and continue" mode.

## Usage

### Automatic (via CLI)

```bash
drake apk analyze sample.apk
# → generates integrity_report.json alongside analysis output
```

### Manual verification

```python
from drake_x.integrity import compute_file_hashes, IntegrityVerifier
from drake_x.integrity.verifier import verify_file_integrity

# Hash a sample
identity = compute_file_hashes(Path("sample.apk"))
print(identity.sha256)

# Verify a file hasn't been tampered with
verify_file_integrity(Path("sample.apk"), expected_sha256="abc...")

# Verify a full integrity report
import json
from drake_x.integrity.models import IntegrityReport
data = json.loads(Path("integrity_report.json").read_text())
report = IntegrityReport(**data)
IntegrityVerifier().verify(report)  # raises on failure
```

## Integrity Report Format

```json
{
  "run_id": "run-a1b2c3d4e5f6",
  "sample_sha256": "deadbeef...",
  "sample_identity": {
    "file_name": "sample.apk",
    "file_size": 1234567,
    "md5": "...",
    "sha1": "...",
    "sha256": "deadbeef..."
  },
  "execution_context": {
    "run_id": "run-a1b2c3d4e5f6",
    "analysis_mode": "apk_analyze",
    "sandbox_enabled": false,
    "network_enabled": false,
    "version_info": { ... }
  },
  "artifacts": [...],
  "custody_events": [...],
  "verified": true,
  "verification_errors": [],
  "report_sha256": "...",
  "generated_at": "2025-01-15T10:30:05+00:00"
}
```

## Optional Integrity Outputs

In addition to the default `integrity_report.json`, three optional
outputs can be enabled per run:

### 1. GPG Signature (`--sign-integrity`)

Produces a detached ASCII-armored signature (`integrity_report.json.asc`)
using the operator's GPG keychain. Signing is optional — missing `gpg`
does not break the pipeline, it just skips signing.

```bash
drake apk analyze sample.apk --sign-integrity
drake apk analyze sample.apk --sign-integrity --signing-key 0xABCDEF12
```

Verify later with:

```python
from drake_x.integrity.signing import verify_signature
ok, details = verify_signature(Path("integrity_report.json"),
                               Path("integrity_report.json.asc"))
```

### 2. STIX 2.1 Provenance Bundle (`--stix-provenance`)

Converts the integrity report into a STIX 2.1 bundle with
`identity`, `file`, `process`, `note`, and `relationship` objects.
Timestamps are frozen for reproducibility.

```bash
drake apk analyze sample.apk --stix-provenance
# → integrity_provenance.stix.json
```

### 3. Append-Only Ledger (`--ledger`)

Persists custody events, integrity reports, and verification results
to a SQLite database in WAL mode. Each entry includes the hash of
the previous entry, creating a linked-hash chain.

```bash
drake apk analyze sample.apk --ledger
# → integrity_ledger.db (in workspace root)
```

Verify the ledger chain:

```python
from drake_x.integrity import IntegrityLedger
ledger = IntegrityLedger(Path("integrity_ledger.db"))
violations = ledger.verify_chain()
assert violations == []  # fail-closed
```

### Combine All

```bash
drake apk analyze sample.apk \
    --sign-integrity \
    --stix-provenance \
    --ledger
```

All three options are also available on `drake pe analyze` and
`drake elf analyze`.

## Module Architecture

```
drake_x/integrity/
├── __init__.py       # Package entry point
├── exceptions.py     # IntegrityError hierarchy
├── hashing.py        # Streaming MD5/SHA-1/SHA-256
├── models.py         # Pydantic models (SampleIdentity, ArtifactRecord, etc.)
├── chain.py          # CustodyChain append-only event log
├── verifier.py       # Fail-closed integrity checker
├── versioning.py     # Pipeline + tool version capture
├── reporting.py      # IntegrityReport builder + finalize outputs
├── signing.py        # GPG detached signatures
├── ledger.py         # Append-only SQLite WAL linked-hash ledger
└── stix_bundle.py    # STIX 2.1 provenance bundle generator
```

## Limitations

1. **Hashes are computed at a point in time** — cannot detect modifications
   that occur after workspace cleanup
2. **External tool versions** are best-effort — some tools don't support
   `--version` reliably
3. **No cryptographic signing** — hashes prove integrity but not authenticity
   (future: consider GPG signing)
4. **No tamper-proof storage** — custody chain is a JSON file, not a
   blockchain or append-only ledger with external anchoring
5. **File-level only** — does not verify in-memory data integrity during
   processing
