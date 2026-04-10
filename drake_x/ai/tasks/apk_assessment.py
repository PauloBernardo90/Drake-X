"""AI task: APK overall threat assessment."""

from __future__ import annotations

from .base import AITask


class ApkAssessmentTask(AITask):
    name = "apk_assessment"
    prompt_file = "task_apk_assessment.md"
    schema = {
        "likely_objective": "string",
        "observed_behaviors": ["string"],
        "analytic_assessment": "string",
        "confidence": "low | medium | high",
        "pending_confirmation": ["string"],
        "caveats": ["string"],
    }
    deterministic = True
    max_evidence_items = 20
