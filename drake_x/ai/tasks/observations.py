"""Turn raw artifact payloads into structured plain-English observations."""

from __future__ import annotations

from .base import AITask


class ObservationsTask(AITask):
    name = "observations"
    prompt_file = "task_summarize.md"   # reuses the summarize template
    schema = {
        "observations": [
            {
                "summary": "string",
                "evidence_pointer": "tool_name + artifact_kind",
                "fact_or_inference": "fact | inference",
            }
        ],
        "caveats": ["string"],
    }
    deterministic = True
    max_evidence_items = 10
