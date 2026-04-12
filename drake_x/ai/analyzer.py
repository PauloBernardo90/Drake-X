"""High-level AI analysis layer.

The analyzer takes normalized artifacts, hands them to a local Ollama model,
parses the JSON response, and produces a list of :class:`Finding` objects
plus a short executive summary string.

If anything goes wrong (Ollama unreachable, JSON broken, model rambles), we
return an empty list and let the caller continue without AI input.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..exceptions import AIUnavailableError
from ..logging import get_logger
from ..models.artifact import Artifact
from ..models.finding import Finding, FindingSeverity, FindingSource
from ..models.target import Target
from .audit import build_record, write_record
from .ollama_client import OllamaClient
from .prompts import ANALYST_SYSTEM_PROMPT, build_analyst_prompt

log = get_logger("ai")


class AIAnalyzer:
    def __init__(self, *, client: OllamaClient) -> None:
        self.client = client

    @property
    def model_name(self) -> str:
        return self.client.model

    async def is_available(self) -> bool:
        return await self.client.is_available()

    async def analyze(
        self,
        *,
        target: Target,
        profile: str,
        artifacts: list[Artifact],
        audit_dir: Path | None = None,
    ) -> tuple[list[Finding], str | None]:
        if not artifacts:
            log.debug("AIAnalyzer.analyze: no artifacts to analyze")
            return [], None

        evidence = [a.model_dump() for a in artifacts]
        prompt = build_analyst_prompt(
            target_display=target.display,
            profile=profile,
            evidence=evidence,
        )

        try:
            raw = await self.client.generate(prompt, system=ANALYST_SYSTEM_PROMPT)
        except AIUnavailableError:
            if audit_dir is not None:
                write_record(
                    build_record(
                        task="analyst_analyzer",
                        model=self.client.model,
                        prompt=prompt,
                        context_node_ids=[],
                        raw_response="",
                        parsed=None,
                        truncation_notes=[],
                        ok=False,
                        error="AIUnavailableError",
                    ),
                    audit_dir,
                )
            raise

        if not raw:
            if audit_dir is not None:
                write_record(
                    build_record(
                        task="analyst_analyzer",
                        model=self.client.model,
                        prompt=prompt,
                        context_node_ids=[],
                        raw_response="",
                        parsed=None,
                        truncation_notes=[],
                        ok=False,
                        error="empty response",
                    ),
                    audit_dir,
                )
            return [], None

        parsed = _safe_json_extract(raw)
        if parsed is None:
            log.warning("AI response was not valid JSON; ignoring")
            if audit_dir is not None:
                write_record(
                    build_record(
                        task="analyst_analyzer",
                        model=self.client.model,
                        prompt=prompt,
                        context_node_ids=[],
                        raw_response=raw,
                        parsed=None,
                        truncation_notes=[],
                        ok=False,
                        error="response was not valid JSON",
                    ),
                    audit_dir,
                )
            return [], None

        summary = parsed.get("executive_summary")
        findings = _parsed_to_findings(parsed)
        if audit_dir is not None:
            write_record(
                build_record(
                    task="analyst_analyzer",
                    model=self.client.model,
                    prompt=prompt,
                    context_node_ids=[],
                    raw_response=raw,
                    parsed=parsed,
                    truncation_notes=[],
                    ok=True,
                    error=None,
                ),
                audit_dir,
            )
        return findings, summary if isinstance(summary, str) else None


def _safe_json_extract(text: str) -> dict[str, Any] | None:
    """Extract a JSON object from a model response.

    Models occasionally wrap JSON in code fences or add a trailing
    sentence. We do a single tolerant extraction step rather than fight
    every possible format.
    """
    text = text.strip()
    if not text:
        return None

    # Strip ``` fences if present.
    if text.startswith("```"):
        text = text.strip("`")
        # remove leading "json" tag if any
        nl = text.find("\n")
        if nl != -1:
            text = text[nl + 1 :]

    # Try the obvious thing first.
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass

    # Find the first balanced {...} block and try that.
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            obj = json.loads(candidate)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None
    return None


_CONFIDENCE_MAP = {"low": 0.3, "medium": 0.6, "high": 0.85}


def _parsed_to_findings(parsed: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    confidence_label = str(parsed.get("confidence", "low")).strip().lower()
    confidence = _CONFIDENCE_MAP.get(confidence_label, 0.4)

    next_steps = _ensure_str_list(parsed.get("recommended_next_safe_steps"))
    caveats = _ensure_str_list(parsed.get("caveats"))

    for obs in _ensure_str_list(parsed.get("notable_observations")):
        findings.append(
            Finding(
                title=_truncate(obs, 90),
                summary=obs,
                severity=FindingSeverity.INFO,
                confidence=confidence,
                source=FindingSource.AI,
                recommended_next_steps=next_steps,
                caveats=caveats,
            )
        )

    for risk in _ensure_str_list(parsed.get("potential_risk_signals")):
        findings.append(
            Finding(
                title=_truncate(f"Risk signal: {risk}", 90),
                summary=risk,
                severity=FindingSeverity.LOW,
                confidence=confidence,
                source=FindingSource.AI,
                recommended_next_steps=next_steps,
                caveats=caveats,
            )
        )

    return findings


def _ensure_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if isinstance(v, (str, int, float))]


def _truncate(value: str, max_len: int) -> str:
    return value if len(value) <= max_len else value[: max_len - 1] + "…"
