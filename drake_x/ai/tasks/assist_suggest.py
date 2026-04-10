"""AI task: Assist Mode next-step suggestion."""

from __future__ import annotations

from .base import AITask


class AssistSuggestTask(AITask):
    name = "assist_suggest"
    prompt_file = "task_assist_suggest.md"
    schema = {
        "suggested_action": "string (e.g. 'run recon_active', 'run headers_audit', 'generate report')",
        "module": "string or null (drake module name if applicable)",
        "reason": "string (1-2 sentences explaining why)",
        "evidence_basis": ["string (findings/artifacts that inform this suggestion)"],
        "confidence": "low | medium | high",
    }
    deterministic = True
    max_evidence_items = 15
