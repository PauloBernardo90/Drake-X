"""Summarize a recon session into an executive triage."""

from __future__ import annotations

from .base import AITask


class SummarizeTask(AITask):
    name = "summarize"
    prompt_file = "task_summarize.md"
    schema = {
        "executive_summary": "string",
        "notable_observations": ["string"],
        "potential_risk_signals": ["string"],
        "confidence": "low | medium | high",
        "recommended_next_safe_steps": ["string"],
        "caveats": ["string"],
    }
    deterministic = True
    max_evidence_items = 8
