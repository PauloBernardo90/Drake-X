"""Shared AI task-execution wrapper with auditability (v1.0).

Before v1.0, only the PE exploit-assessment path wrote an audit log.
This module generalizes the wrap-and-audit pattern so any AI task
invocation — PE, generic ``drake ai``, or future domains — runs
through the same audited path.

Contract:

- The wrapper reconstructs the exact prompt that will be sent to the
  model (same call chain the task uses) and hashes it.
- It writes an audit record whether or not the model answers, whether
  or not the response is valid JSON, whether or not the runtime is
  reachable.
- It accepts the task's graph-aware context node IDs and truncation
  notes so attribution is accurate.

The record shape is :class:`drake_x.ai.audit.AIAuditRecord` — nothing
new invented here.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from ..logging import get_logger
from .audit import build_record, write_record
from .ollama_client import OllamaClient
from .tasks.base import AITask, AITaskResult, TaskContext

log = get_logger("ai.audited_run")


def run_audited(
    *,
    task: AITask,
    context: TaskContext,
    client: OllamaClient,
    audit_dir: Path | None,
    context_node_ids: list[str] | None = None,
    truncation_notes: list[str] | None = None,
) -> AITaskResult:
    """Run *task* with *context* through *client* and always audit.

    ``context_node_ids`` and ``truncation_notes`` are accepted from the
    caller so audit attribution matches what the context builder
    actually did. Tasks that do not use graph retrieval can pass empty
    lists.

    Never raises. On any failure (prompt build, unreachable model,
    invalid JSON), an audit record is still written and a failure
    ``AITaskResult`` is returned.
    """
    context_node_ids = list(context_node_ids or [])
    truncation_notes = list(truncation_notes or [])

    # Reproduce the exact prompt for hashing.
    try:
        prompt = task._build_prompt(context)  # noqa: SLF001 — auditing needs the exact text
    except Exception as exc:  # noqa: BLE001
        log.warning("prompt build failed for %s: %s", task.name, exc)
        if audit_dir is not None:
            write_record(
                build_record(
                    task=task.name, model=client.model, prompt="",
                    context_node_ids=context_node_ids, raw_response="",
                    parsed=None, truncation_notes=truncation_notes,
                    ok=False, error=f"prompt build failed: {exc}",
                ),
                audit_dir,
            )
        return AITaskResult(task_name=task.name, ok=False, error=f"prompt build failed: {exc}")

    try:
        task_result = asyncio.run(task.run(client=client, context=context))
    except Exception as exc:  # noqa: BLE001
        log.warning("task %s raised: %s", task.name, exc)
        if audit_dir is not None:
            write_record(
                build_record(
                    task=task.name, model=client.model, prompt=prompt,
                    context_node_ids=context_node_ids, raw_response="",
                    parsed=None, truncation_notes=truncation_notes,
                    ok=False, error=f"task execution raised: {exc}",
                ),
                audit_dir,
            )
        return AITaskResult(task_name=task.name, ok=False, error=f"task raised: {exc}")

    if audit_dir is not None:
        write_record(
            build_record(
                task=task.name, model=client.model, prompt=prompt,
                context_node_ids=context_node_ids,
                raw_response=task_result.raw_text or "",
                parsed=task_result.parsed,
                truncation_notes=truncation_notes,
                ok=task_result.ok,
                error=task_result.error,
            ),
            audit_dir,
        )
    return task_result
