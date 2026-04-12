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
                "cwe": ["CWE-79"],
                "owasp": ["A03:2021"],
                "mitre_attck": ["T1059"],
                "rationale": "string",
            }
        ]
    }
    deterministic = True
    max_evidence_items = 12
