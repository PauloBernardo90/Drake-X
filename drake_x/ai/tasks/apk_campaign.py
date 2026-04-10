"""AI task: APK campaign similarity assessment."""

from __future__ import annotations

from .base import AITask


class ApkCampaignTask(AITask):
    name = "apk_campaign"
    prompt_file = "task_apk_campaign.md"
    schema = {
        "assessments": [
            {
                "category": "string",
                "similarity": "consistent_with | shares_traits | tentatively_resembles | insufficient_evidence",
                "matching_traits": ["string"],
                "confidence": "low | medium | high",
                "rationale": "string",
            }
        ],
        "overall_notes": "string",
        "pending_confirmation": ["string"],
    }
    deterministic = True
    max_evidence_items = 25
