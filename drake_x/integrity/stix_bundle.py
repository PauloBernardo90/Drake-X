"""STIX 2.1 provenance bundle generator for integrity reports.

Converts an :class:`IntegrityReport` into a STIX 2.1 bundle containing:

- ``identity`` SDO: the Drake-X analysis engine
- ``file`` SCO: the sample observable (SHA-256, MD5, SHA-1, size)
- ``process`` SDO: the analysis execution context
- ``note`` SDOs: custody events
- ``relationship`` SROs: linking events to the sample

All timestamps are frozen to a deterministic sentinel for byte-level
reproducibility, following the same convention as
``drake_x.reporting.detection_writer``.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, TYPE_CHECKING

from .. import __version__ as _drake_version

if TYPE_CHECKING:
    from .models import IntegrityReport

_STIX_TIMESTAMP_SENTINEL = "1970-01-01T00:00:00+00:00"


def render_provenance_stix(report: IntegrityReport) -> str:
    """Build a STIX 2.1 provenance bundle from an integrity report.

    Returns the bundle as a JSON string. Returns empty string if the
    report has no sample SHA-256.
    """
    if not report.sample_sha256:
        return ""

    ts = _STIX_TIMESTAMP_SENTINEL
    sha = report.sample_sha256

    bundle_id = f"bundle--{_stable_uuid('provenance-bundle', report.run_id)}"

    # Drake-X identity SDO
    identity_id = f"identity--{_stable_uuid('drake-x-identity', 'drake-x')}"
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": ts,
        "modified": ts,
        "name": "Drake-X Analysis Engine",
        "identity_class": "system",
        "description": (
            f"Drake-X v{_drake_version} — local-first evidence-driven "
            "malware analysis platform."
        ),
    }

    # File observable (the sample)
    file_id = f"file--{_uuid_from_sha(sha)}"
    identity_info = report.sample_identity or {}
    file_obj: dict[str, Any] = {
        "type": "file",
        "spec_version": "2.1",
        "id": file_id,
        "hashes": {"SHA-256": sha},
    }
    if identity_info.get("md5"):
        file_obj["hashes"]["MD5"] = identity_info["md5"]
    if identity_info.get("sha1"):
        file_obj["hashes"]["SHA-1"] = identity_info["sha1"]
    if identity_info.get("file_size"):
        file_obj["size"] = identity_info["file_size"]
    if identity_info.get("file_name"):
        file_obj["name"] = identity_info["file_name"]

    # Process SDO for the analysis execution
    process_id = f"process--{_stable_uuid('analysis-process', report.run_id)}"
    process = {
        "type": "process",
        "spec_version": "2.1",
        "id": process_id,
        "created": ts,
        "modified": ts,
        "command_line": (
            f"drake {report.execution_context.analysis_mode} "
            f"(run_id={report.run_id})"
        ),
        "image_ref": file_id,
    }

    objects: list[dict[str, Any]] = [identity, file_obj, process]

    # Notes for each custody event
    for i, event in enumerate(report.custody_events):
        note_id = f"note--{_stable_uuid('custody-note', f'{report.run_id}:{i}')}"
        abstract = f"Custody event [{event.action.value}] by {event.actor or 'drake-x'}"
        objects.append({
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": ts,
            "modified": ts,
            "abstract": abstract,
            "content": (
                f"{event.details} "
                f"(status={event.status.value}, "
                f"artifact_sha256={event.artifact_sha256[:16] if event.artifact_sha256 else 'n/a'}…)"
            ),
            "object_refs": [file_id, process_id],
            "labels": ["custody-event", f"action-{event.action.value}"],
        })

        # Relationship: note → process
        rel_id = f"relationship--{_stable_uuid('note-rel', f'{report.run_id}:{i}')}"
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": ts,
            "modified": ts,
            "relationship_type": "related-to",
            "source_ref": note_id,
            "target_ref": process_id,
        })

    # Notes for each artifact
    for i, art in enumerate(report.artifacts):
        if not art.sha256:
            continue
        note_id = f"note--{_stable_uuid('artifact-note', f'{report.run_id}:art:{i}')}"
        objects.append({
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": ts,
            "modified": ts,
            "abstract": f"Artifact: {art.artifact_type}",
            "content": (
                f"file_name={art.file_name}, sha256={art.sha256}, "
                f"size={art.file_size}, parent_sha256={art.parent_sha256[:16]}…"
            ),
            "object_refs": [file_id, process_id],
            "labels": ["artifact-record", f"type-{art.artifact_type}"],
        })

    # Relationship: process → sample (analyzes)
    analysis_rel_id = f"relationship--{_stable_uuid('analysis-rel', report.run_id)}"
    objects.append({
        "type": "relationship",
        "spec_version": "2.1",
        "id": analysis_rel_id,
        "created": ts,
        "modified": ts,
        "relationship_type": "analyzes",
        "source_ref": process_id,
        "target_ref": file_id,
    })

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
        "x_drake_x": {
            "generator_version": _drake_version,
            "analysis_type": "integrity_provenance",
            "run_id": report.run_id,
            "pipeline_version": report.version_info.pipeline_version,
            "analysis_profile": report.version_info.analysis_profile,
            "integrity_verified": report.verified,
            "report_sha256": report.report_sha256,
            "bundle_note": (
                "This STIX bundle captures the provenance and custody chain "
                "of a Drake-X analysis run. Timestamps are frozen for "
                "reproducibility; real timestamps are in the source "
                "integrity report."
            ),
        },
    }
    return json.dumps(bundle, indent=2, default=str)


def _uuid_from_sha(sha256: str) -> str:
    """Produce a stable UUID from a SHA-256 hex digest."""
    return str(uuid.uuid5(uuid.NAMESPACE_OID, sha256))


def _stable_uuid(kind: str, key: str) -> str:
    """Derive a deterministic UUID for (kind, key)."""
    return str(uuid.uuid5(uuid.NAMESPACE_OID, f"drake-x:provenance:{kind}:{key}"))
