"""Shared scaffolding for AI tasks."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...exceptions import AIUnavailableError
from ...logging import get_logger
from ..ollama_client import OllamaClient

log = get_logger("ai.task")


# Resolve the on-disk prompts directory once. The package layout is:
#   <repo>/prompts/*.md
#   <repo>/drake_x/ai/tasks/base.py
PROMPTS_DIR = Path(__file__).resolve().parents[3] / "prompts"


@dataclass
class TaskContext:
    """Per-call inputs an AI task receives.

    The context intentionally does NOT carry the engagement scope file —
    AI prompts must never see authorization metadata.

    ``graph_context`` is an optional dict produced by
    :func:`drake_x.graph.context.serialize_graph_context`. When present,
    the AI prompt includes structured graph relationships alongside the
    flat evidence list. When absent, prompts fall back to the flat
    evidence pipeline (backward-compatible with all v0.3/v0.4 tasks).
    """

    target_display: str
    profile: str
    session_id: str | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    graph_context: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AITaskResult:
    """Structured outcome of one AI task call."""

    task_name: str
    ok: bool
    parsed: dict[str, Any] | None = None
    raw_text: str | None = None
    error: str | None = None


class AITask:
    """Base class for AI tasks. Subclasses set name/prompt/schema."""

    name: str = "base"
    prompt_file: str = ""
    schema: dict[str, Any] = {}
    deterministic: bool = True
    max_evidence_items: int = 8
    max_payload_chars: int = 800

    def __init__(self, *, prompts_dir: Path | None = None) -> None:
        self.prompts_dir = prompts_dir or PROMPTS_DIR

    # ----- public API --------------------------------------------------

    async def run(self, *, client: OllamaClient, context: TaskContext) -> AITaskResult:
        try:
            prompt = self._build_prompt(context)
        except Exception as exc:  # noqa: BLE001
            return AITaskResult(task_name=self.name, ok=False, error=f"prompt error: {exc}")

        system_prompt = self._load_system_prompt()
        try:
            raw = await client.generate(prompt, system=system_prompt)
        except AIUnavailableError as exc:
            return AITaskResult(task_name=self.name, ok=False, error=str(exc))
        except Exception as exc:  # noqa: BLE001
            return AITaskResult(task_name=self.name, ok=False, error=f"client error: {exc}")

        parsed = _safe_json_extract(raw)
        if parsed is None:
            log.warning("AI task %s: response was not valid JSON; ignoring", self.name)
            return AITaskResult(
                task_name=self.name,
                ok=False,
                raw_text=raw,
                error="model response was not valid JSON",
            )

        return AITaskResult(task_name=self.name, ok=True, parsed=parsed, raw_text=raw)

    # ----- prompt assembly --------------------------------------------

    def _build_prompt(self, context: TaskContext) -> str:
        template = self._load_template(self.prompt_file)

        # When graph context is available, prepend it as a structured
        # EVIDENCE GRAPH section before the flat evidence. This gives the
        # model relationship data alongside raw observations. If absent,
        # the placeholder is empty — backward-compatible with all prompts.
        graph_section = ""
        if context.graph_context:
            graph_section = (
                "EVIDENCE GRAPH (structured relationships between findings):\n"
                + json.dumps(context.graph_context, indent=2, default=str)
                + "\n\n"
            )

        return template.format(
            target_display=context.target_display,
            profile=context.profile,
            session_id=context.session_id or "(unknown)",
            evidence_json=graph_section + self._trim_json(context.evidence),
            findings_json=self._trim_json(context.findings),
            observations_json=self._trim_json(context.evidence),
            schema_json=json.dumps(self.schema, indent=2),
        )

    def _load_template(self, name: str) -> str:
        if not name:
            raise ValueError(f"task {self.name} has no prompt_file set")
        path = self.prompts_dir / name
        if not path.exists():
            raise FileNotFoundError(f"prompt template not found: {path}")
        return path.read_text(encoding="utf-8")

    def _load_system_prompt(self) -> str:
        path = self.prompts_dir / "system_analyst.md"
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")

    def _trim_json(self, items: list[dict[str, Any]]) -> str:
        trimmed = [self._trim_item(it) for it in items[: self.max_evidence_items]]
        return json.dumps(trimmed, indent=2, default=str)

    def _trim_item(self, item: dict[str, Any]) -> dict[str, Any]:
        out = dict(item)
        payload = out.get("payload")
        if payload is not None:
            text = json.dumps(payload, default=str)
            if len(text) > self.max_payload_chars:
                out["payload"] = {
                    "_truncated": True,
                    "_excerpt": text[: self.max_payload_chars],
                }
        return out


# ----- helpers ---------------------------------------------------------------


def _safe_json_extract(text: str) -> dict[str, Any] | None:
    """Extract a JSON object from a model response."""
    text = text.strip()
    if not text:
        return None
    if text.startswith("```"):
        text = text.strip("`")
        nl = text.find("\n")
        if nl != -1:
            text = text[nl + 1 :]
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            obj = json.loads(text[start : end + 1])
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None
    return None
