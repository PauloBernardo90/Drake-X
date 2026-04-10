"""AI task: APK obfuscation analysis."""

from __future__ import annotations

from .base import AITask


class ApkObfuscationTask(AITask):
    name = "apk_obfuscation"
    prompt_file = "task_apk_obfuscation.md"
    schema = {
        "techniques": [
            {
                "technique": "string",
                "evidence": ["string"],
                "confidence": "low | medium | high",
            }
        ],
        "overall_assessment": "string",
        "pending_confirmation": ["string"],
    }
    deterministic = True
    max_evidence_items = 15
