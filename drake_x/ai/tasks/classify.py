"""Classify observations into severity + CWE/OWASP/MITRE buckets."""

from __future__ import annotations

from .base import AITask


class ClassifyTask(AITask):
    name = "classify"
    prompt_file = "task_classify.md"
    schema = {
        "classifications": [
            {
                "observation": "string",
                "severity": "info | low | medium | high | critical",
                "confidence": "low | medium | high",
                "cwe": ["CWE-XXX"],
                "owasp": ["A0X:YYYY"],
                "mitre_attck": ["TXXXX"],
                "rationale": "string",
            }
        ]
    }
    deterministic = True
    max_evidence_items = 12
