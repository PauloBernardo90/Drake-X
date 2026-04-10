"""Suggest the next SAFE recon steps for an analyst."""

from __future__ import annotations

from .base import AITask


class NextStepsTask(AITask):
    name = "next_steps"
    prompt_file = "task_next_steps.md"
    schema = {
        "safe_next_steps": ["string"],
        "rationale": "string",
        "caveats": ["string"],
    }
    deterministic = True
    max_evidence_items = 8
