"""AI audit log — deterministic record of every LLM call Drake-X makes.

Drake-X's evidence-first doctrine requires that every AI-assisted
assessment is reproducible and inspectable. This module records, for
each task invocation:

- task name and timestamp
- model identifier
- SHA-256 of the exact prompt sent
- sorted list of evidence-graph node IDs the prompt was built from
- raw response text
- parsed response (if JSON extraction succeeded)
- truncation notes when context was bounded

The audit log is an append-only JSON Lines file written under the
workspace's ``ai_audit/`` directory. It is not sent anywhere. Inspection
is a local-first operation.

This does **not** try to replace a full eval harness; it is a compliance
primitive for "what did the model see, and what did it answer?" It is
intentionally small, synchronous, and dependency-free.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..logging import get_logger

log = get_logger("ai.audit")


@dataclass(frozen=True)
class AIAuditRecord:
    """One entry in the AI audit log.

    Field order and types are stable across releases. Backward
    compatibility: readers must tolerate new optional fields being added
    with default values.
    """

    task: str
    model: str
    timestamp: str  # ISO-8601, UTC
    prompt_sha256: str
    context_node_ids: list[str] = field(default_factory=list)
    raw_response: str = ""
    parsed: dict[str, Any] | None = None
    truncation_notes: list[str] = field(default_factory=list)
    ok: bool = True
    error: str | None = None
    prompt_chars: int = 0
    response_chars: int = 0

    def to_json_line(self) -> str:
        """Serialize as a single JSON line for the append-only log."""
        return json.dumps(asdict(self), default=str, sort_keys=True)


def build_record(
    *,
    task: str,
    model: str,
    prompt: str,
    context_node_ids: list[str],
    raw_response: str,
    parsed: dict[str, Any] | None,
    truncation_notes: list[str] | None = None,
    ok: bool = True,
    error: str | None = None,
) -> AIAuditRecord:
    """Construct an audit record with a deterministic prompt hash.

    ``context_node_ids`` is sorted before hashing/writing so that the
    same inputs always produce the same record regardless of call
    ordering upstream.
    """
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    return AIAuditRecord(
        task=task,
        model=model,
        timestamp=_dt.datetime.now(tz=_dt.timezone.utc).isoformat(timespec="seconds"),
        prompt_sha256=prompt_hash,
        context_node_ids=sorted(set(context_node_ids)),
        raw_response=raw_response or "",
        parsed=parsed,
        truncation_notes=list(truncation_notes or []),
        ok=ok,
        error=error,
        prompt_chars=len(prompt or ""),
        response_chars=len(raw_response or ""),
    )


def write_record(record: AIAuditRecord, audit_dir: Path) -> Path:
    """Append *record* to the audit log under *audit_dir*.

    One file per task name (``ai_audit/<task>.jsonl``). The directory is
    created if necessary. Returns the path written to.
    """
    audit_dir = Path(audit_dir)
    audit_dir.mkdir(parents=True, exist_ok=True)
    target = audit_dir / f"{record.task}.jsonl"
    with target.open("a", encoding="utf-8") as fh:
        fh.write(record.to_json_line())
        fh.write("\n")
    log.debug("AI audit: appended %s record to %s", record.task, target)
    return target


def read_records(audit_dir: Path, task: str) -> list[AIAuditRecord]:
    """Read all records for *task* from *audit_dir*.

    Tolerates unknown/new fields (forward-compat). Malformed lines are
    skipped with a warning rather than raising — audit reads must not
    crash a running session.
    """
    target = Path(audit_dir) / f"{task}.jsonl"
    if not target.exists():
        return []
    out: list[AIAuditRecord] = []
    for i, raw in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as exc:
            log.warning("audit log %s:%d malformed: %s", target, i, exc)
            continue
        try:
            out.append(AIAuditRecord(
                task=str(obj.get("task", task)),
                model=str(obj.get("model", "")),
                timestamp=str(obj.get("timestamp", "")),
                prompt_sha256=str(obj.get("prompt_sha256", "")),
                context_node_ids=list(obj.get("context_node_ids", [])),
                raw_response=str(obj.get("raw_response", "")),
                parsed=obj.get("parsed"),
                truncation_notes=list(obj.get("truncation_notes", [])),
                ok=bool(obj.get("ok", True)),
                error=obj.get("error"),
                prompt_chars=int(obj.get("prompt_chars", 0)),
                response_chars=int(obj.get("response_chars", 0)),
            ))
        except (TypeError, ValueError) as exc:
            log.warning("audit log %s:%d coerce failure: %s", target, i, exc)
    return out
