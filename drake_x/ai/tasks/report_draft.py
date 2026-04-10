"""Draft executive + technical report sections."""

from __future__ import annotations

from .base import AITask


class ReportDraftTask(AITask):
    name = "report_draft"
    prompt_file = "task_report_draft.md"
    schema = {
        "executive_summary": "string",
        "technical_summary": "string",
        "caveats": ["string"],
    }
    deterministic = True
    max_evidence_items = 12
