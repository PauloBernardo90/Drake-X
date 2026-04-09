"""Recon orchestrator.

The orchestrator is the only place that decides:

- which tools run, in what order, and against what target
- whether to run them concurrently
- how their results are normalized and persisted
- when (and whether) to call the AI analyzer

It calls into the registry for tool selection, into the tools for execution,
into the normalizers for parsing, and into the session store for persistence.
It deliberately does NOT do any of those things itself.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime

from .ai.analyzer import AIAnalyzer
from .config import DrakeXConfig
from .logging import get_logger
from .models.artifact import Artifact
from .models.finding import Finding
from .models.session import Session
from .models.target import Target
from .models.tool_result import ToolResult, ToolResultStatus
from .normalize import normalize_result
from .registry import ToolEntry, ToolRegistry
from .session_store import SessionStore

log = get_logger("orchestrator")


@dataclass
class ScanReport:
    """The complete output of one scan run."""

    session: Session
    tool_results: list[ToolResult]
    artifacts: list[Artifact]
    findings: list[Finding]


class Orchestrator:
    def __init__(
        self,
        *,
        config: DrakeXConfig,
        registry: ToolRegistry,
        store: SessionStore,
        ai: AIAnalyzer | None = None,
    ) -> None:
        self.config = config
        self.registry = registry
        self.store = store
        self.ai = ai

    async def run_scan(
        self,
        target: Target,
        *,
        profile: str,
        tool_timeout: int | None = None,
        ai_enabled: bool = False,
    ) -> ScanReport:
        timeout = tool_timeout or self.config.default_timeout
        eligible, missing = self.registry.select_for(profile=profile, target=target)

        session = Session(
            target=target,
            profile=profile,
            tools_planned=[e.name for e in eligible],
            tools_skipped=[e.name for e in missing],
            ai_enabled=ai_enabled and self.ai is not None,
            ai_model=self.ai.model_name if (ai_enabled and self.ai is not None) else None,
        )

        for m in missing:
            session.warnings.append(f"tool {m.name!r} skipped: not installed")

        session.mark_running()
        # Persist immediately so failed runs still leave a trace.
        self.store.save_session(session)

        if not eligible:
            session.warnings.append("no eligible tools to run for this profile/target combination")
            session.mark_finished(partial=True)
            self.store.save_session(session)
            return ScanReport(session=session, tool_results=[], artifacts=[], findings=[])

        # Split tools into "parallel-safe" and "serial". We run the parallel
        # batch concurrently and the serial ones one after another. This keeps
        # network noise predictable while still being faster than pure serial.
        parallel = [e for e in eligible if e.cls.meta.parallel_safe]
        serial = [e for e in eligible if not e.cls.meta.parallel_safe]

        results: list[ToolResult] = []

        if parallel:
            log.debug("running %d tools in parallel: %s", len(parallel), [e.name for e in parallel])
            results.extend(await self._run_parallel(parallel, target, timeout))

        for entry in serial:
            log.debug("running serial tool %s", entry.name)
            results.append(await self._run_one(entry, target, timeout))

        for r in results:
            self.store.save_tool_result(session.id, r)
            if r.ran:
                session.tools_ran.append(r.tool_name)
                if r.status == ToolResultStatus.NONZERO:
                    # NONZERO is conservative-by-default: it counts as "ran"
                    # but always raises a warning and forces a partial session
                    # so an analyst notices something odd happened.
                    session.warnings.append(
                        f"tool {r.tool_name!r} exited non-zero "
                        f"(exit_code={r.exit_code}); artifact is degraded"
                    )
            elif r.status == ToolResultStatus.NOT_INSTALLED:
                if r.tool_name not in session.tools_skipped:
                    session.tools_skipped.append(r.tool_name)
            elif r.status == ToolResultStatus.TIMEOUT:
                session.warnings.append(f"tool {r.tool_name!r} timed out after {timeout}s")
            elif r.status == ToolResultStatus.ERROR:
                session.warnings.append(f"tool {r.tool_name!r} errored: {r.error_message}")

        artifacts: list[Artifact] = []
        for r in results:
            artifact = normalize_result(r)
            if artifact is None:
                continue
            artifacts.append(artifact)
            self.store.save_artifact(session.id, artifact)

        findings: list[Finding] = []
        if session.ai_enabled and self.ai is not None:
            try:
                ai_findings, summary = await self.ai.analyze(target=target, profile=profile, artifacts=artifacts)
                findings.extend(ai_findings)
                session.ai_summary = summary
                for f in ai_findings:
                    self.store.save_finding(session.id, f)
            except Exception as exc:  # noqa: BLE001 — AI failures must never break a scan
                log.warning("AI analysis failed, continuing without it: %s", exc)
                session.warnings.append(f"AI analysis unavailable: {exc}")
                session.ai_enabled = False

        partial = any(
            r.status
            in {
                ToolResultStatus.NONZERO,
                ToolResultStatus.TIMEOUT,
                ToolResultStatus.ERROR,
                ToolResultStatus.NOT_INSTALLED,
            }
            for r in results
        ) or bool(session.warnings)

        session.mark_finished(partial=partial)
        self.store.save_session(session)

        return ScanReport(session=session, tool_results=results, artifacts=artifacts, findings=findings)

    # ----- internals ---------------------------------------------------

    async def _run_one(self, entry: ToolEntry, target: Target, timeout: int) -> ToolResult:
        """Run a single tool, converting any unexpected exception into an
        ``ERROR`` :class:`ToolResult`.

        Tool wrappers are supposed to absorb routine subprocess failures and
        return a structured result. We treat anything else (a buggy adapter,
        a third-party plug-in, etc.) as a wrapper failure and record it
        without aborting the rest of the scan.
        """
        started = datetime.now(UTC)
        try:
            tool = self.registry.instantiate(entry)
            return await tool.run(target, timeout=timeout)
        except asyncio.CancelledError:
            # Cooperative cancellation must propagate so the event loop can
            # tear the task down cleanly.
            raise
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            log.exception("tool wrapper for %s raised unexpectedly", entry.name)
            finished = datetime.now(UTC)
            return ToolResult(
                tool_name=entry.name,
                command=[entry.binary],
                started_at=started,
                finished_at=finished,
                duration_seconds=(finished - started).total_seconds(),
                exit_code=None,
                status=ToolResultStatus.ERROR,
                error_message=f"wrapper exception: {type(exc).__name__}: {exc}",
            )

    async def _run_parallel(
        self, entries: list[ToolEntry], target: Target, timeout: int
    ) -> list[ToolResult]:
        """Run several tools concurrently. One tool blowing up cannot remove
        results from the others — we use ``return_exceptions=True`` and
        convert any leaked exception into an ``ERROR`` result tied to the
        entry that produced it. ``_run_one`` is already exception-safe; this
        is belt-and-braces."""

        tasks = [self._run_one(e, target, timeout) for e in entries]
        raw = await asyncio.gather(*tasks, return_exceptions=True)

        results: list[ToolResult] = []
        now = datetime.now(UTC)
        for entry, item in zip(entries, raw, strict=True):
            if isinstance(item, BaseException):
                if isinstance(item, asyncio.CancelledError):
                    raise item
                log.exception("parallel tool %s leaked an exception", entry.name, exc_info=item)
                results.append(
                    ToolResult(
                        tool_name=entry.name,
                        command=[entry.binary],
                        started_at=now,
                        finished_at=now,
                        duration_seconds=0.0,
                        exit_code=None,
                        status=ToolResultStatus.ERROR,
                        error_message=f"wrapper exception: {type(item).__name__}: {item}",
                    )
                )
            else:
                results.append(item)
        return results
