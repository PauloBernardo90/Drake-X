"""Session-to-session artifact diff.

Compares the artifacts from two sessions targeting the same host and
produces a structured delta listing:

- **added** observations that appear in session B but not A
- **removed** observations that appear in A but not B
- **changed** observations where the same artifact kind / tool exists in
  both sessions but the payload differs

This is useful for tracking changes in a target's attack surface over
successive scans: "what ports opened since last week?", "did the HSTS
header appear?", "was that directory still reachable?".

The diff is purely artifact-based — no network calls. It compares the
JSON payloads stored in the workspace database.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..models.artifact import Artifact


@dataclass
class DiffEntry:
    """One row in the diff output."""

    change: str                      # "added" | "removed" | "changed"
    kind: str                        # artifact kind
    tool_name: str
    summary: str                     # human-readable one-liner
    detail: dict[str, Any] | None    # payload excerpt or delta


@dataclass
class SessionDiff:
    """Complete diff between two sessions."""

    session_a_id: str
    session_b_id: str
    entries: list[DiffEntry]

    @property
    def added(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change == "added"]

    @property
    def removed(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change == "removed"]

    @property
    def changed(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change == "changed"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_a": self.session_a_id,
            "session_b": self.session_b_id,
            "added_count": len(self.added),
            "removed_count": len(self.removed),
            "changed_count": len(self.changed),
            "entries": [
                {
                    "change": e.change,
                    "kind": e.kind,
                    "tool_name": e.tool_name,
                    "summary": e.summary,
                    "detail": e.detail,
                }
                for e in self.entries
            ],
        }

    def to_markdown(self) -> str:
        lines: list[str] = []
        lines.append(f"# Surface diff: `{self.session_a_id}` → `{self.session_b_id}`\n")
        lines.append(
            f"| Change | Count |\n|--------|-------|\n"
            f"| Added | {len(self.added)} |\n"
            f"| Removed | {len(self.removed)} |\n"
            f"| Changed | {len(self.changed)} |\n"
        )
        if self.added:
            lines.append("## Added\n")
            for e in self.added:
                lines.append(f"- **{e.kind}** ({e.tool_name}): {e.summary}")
        if self.removed:
            lines.append("\n## Removed\n")
            for e in self.removed:
                lines.append(f"- **{e.kind}** ({e.tool_name}): {e.summary}")
        if self.changed:
            lines.append("\n## Changed\n")
            for e in self.changed:
                lines.append(f"- **{e.kind}** ({e.tool_name}): {e.summary}")
        lines.append("")
        return "\n".join(lines)


def diff_sessions(
    *,
    session_a_id: str,
    session_b_id: str,
    artifacts_a: list[Artifact],
    artifacts_b: list[Artifact],
) -> SessionDiff:
    """Produce a structured diff between artifacts from two sessions.

    Artifacts are matched by ``(kind, tool_name)``. Within each pair,
    payloads are compared as serialized JSON — if they differ, the entry
    is marked *changed* and a summary of the delta is included.
    """
    index_a = _build_index(artifacts_a)
    index_b = _build_index(artifacts_b)

    entries: list[DiffEntry] = []

    all_keys = sorted(set(index_a) | set(index_b))
    for key in all_keys:
        kind, tool = key
        art_a = index_a.get(key)
        art_b = index_b.get(key)

        if art_a is None and art_b is not None:
            entries.append(DiffEntry(
                change="added",
                kind=kind,
                tool_name=tool,
                summary=_summarize_payload(art_b.payload),
                detail=art_b.payload,
            ))
        elif art_b is None and art_a is not None:
            entries.append(DiffEntry(
                change="removed",
                kind=kind,
                tool_name=tool,
                summary=_summarize_payload(art_a.payload),
                detail=art_a.payload,
            ))
        elif art_a is not None and art_b is not None:
            json_a = json.dumps(art_a.payload, sort_keys=True, default=str)
            json_b = json.dumps(art_b.payload, sort_keys=True, default=str)
            if json_a != json_b:
                delta = _compute_delta(art_a.payload, art_b.payload)
                entries.append(DiffEntry(
                    change="changed",
                    kind=kind,
                    tool_name=tool,
                    summary=_delta_summary(delta),
                    detail=delta,
                ))

    return SessionDiff(
        session_a_id=session_a_id,
        session_b_id=session_b_id,
        entries=entries,
    )


# ----- internals -------------------------------------------------------------


def _build_index(artifacts: list[Artifact]) -> dict[tuple[str, str], Artifact]:
    """Index artifacts by ``(kind, tool_name)``.

    When there are duplicates (e.g. two nmap artifacts) keep the one
    with the higher confidence.
    """
    idx: dict[tuple[str, str], Artifact] = {}
    for art in artifacts:
        key = (art.kind, art.tool_name)
        existing = idx.get(key)
        if existing is None or art.confidence > existing.confidence:
            idx[key] = art
    return idx


def _summarize_payload(payload: dict[str, Any]) -> str:
    """Produce a one-liner from a payload dict."""
    parts: list[str] = []
    for key in ("records", "hosts", "technologies", "hits", "endpoints", "hit_count", "open_port_count"):
        val = payload.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            parts.append(f"{key}: {len(val)} item(s)")
        elif isinstance(val, dict):
            parts.append(f"{key}: {len(val)} key(s)")
        else:
            parts.append(f"{key}={val}")
    return "; ".join(parts) if parts else f"{len(payload)} key(s) in payload"


def _compute_delta(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Produce a structured delta between two payload dicts.

    Returns a dict with ``added_keys``, ``removed_keys``, and
    ``changed_keys`` for top-level differences. Not recursive — deep
    diffs are out of scope for v0.3.
    """
    keys_a = set(a.keys())
    keys_b = set(b.keys())
    added_keys = sorted(keys_b - keys_a)
    removed_keys = sorted(keys_a - keys_b)
    changed_keys: list[str] = []
    for k in sorted(keys_a & keys_b):
        if json.dumps(a[k], sort_keys=True, default=str) != json.dumps(b[k], sort_keys=True, default=str):
            changed_keys.append(k)

    return {
        "added_keys": added_keys,
        "removed_keys": removed_keys,
        "changed_keys": changed_keys,
    }


def _delta_summary(delta: dict[str, Any]) -> str:
    parts: list[str] = []
    if delta.get("added_keys"):
        parts.append(f"+{len(delta['added_keys'])} key(s)")
    if delta.get("removed_keys"):
        parts.append(f"-{len(delta['removed_keys'])} key(s)")
    if delta.get("changed_keys"):
        parts.append(f"~{len(delta['changed_keys'])} key(s)")
    return ", ".join(parts) if parts else "payload changed"
