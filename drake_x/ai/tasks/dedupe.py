"""Dedupe-task: ask the local LLM to group duplicate findings.

The task receives a session's findings, asks the model to group ones
that describe the same underlying observation, and returns a JSON
document of groups. Each group designates one ``canonical_id`` and a
list of ``duplicate_ids``.

The task itself never mutates storage. The CLI consumer
(``drake ai dedupe ... --apply``) takes the parsed result and writes a
``duplicate-of:<canonical-id>`` tag onto each duplicate via
:meth:`drake_x.core.storage.WorkspaceStorage.update_finding_tags`.
"""

from __future__ import annotations

from .base import AITask


class DedupeTask(AITask):
    name = "dedupe"
    prompt_file = "task_dedupe.md"
    schema = {
        "groups": [
            {
                "canonical_id": "string (finding id, e.g. f-abc12345)",
                "duplicate_ids": ["string (finding ids)"],
                "rationale": "string",
            }
        ]
    }
    deterministic = True
    # Findings can run into the dozens for a busy session. Bump the cap
    # so the model sees them all.
    max_evidence_items = 64
