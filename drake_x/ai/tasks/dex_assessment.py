"""AI task: DEX deep analysis threat assessment.

Takes structured DEX analysis evidence (sensitive APIs, obfuscation
signals, string IoCs, multi-DEX indicators) and asks the local LLM
to produce a coherent threat assessment tying the signals together.

This task does NOT replace the deterministic analysis — it synthesizes
findings into a narrative for the analyst, identifying patterns that
span multiple detector outputs.
"""

from __future__ import annotations

from .base import AITask


class DexAssessmentTask(AITask):
    name = "dex_assessment"
    prompt_file = "task_dex_assessment.md"
    schema = {
        "threat_summary": "string",
        "likely_malware_family": "string | null",
        "key_behaviors": [
            {
                "behavior": "string",
                "evidence": ["string"],
                "severity": "low | medium | high | critical",
            }
        ],
        "obfuscation_assessment": "string",
        "evasion_techniques": ["string"],
        "target_profile": "string",
        "confidence": "low | medium | high",
        "pending_confirmation": ["string"],
        "caveats": ["string"],
    }
    deterministic = True
    max_evidence_items = 30
    max_payload_chars = 1200
