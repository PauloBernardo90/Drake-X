"""Workspace-aware execution engine.

The engine is the v2 evolution of :class:`drake_x.orchestrator.Orchestrator`.
It composes the same execution primitives (tool wrappers, normalizers,
storage) but adds:

- engagement scope enforcement (refuses out-of-scope targets)
- active-vs-passive policy classification
- operator confirmation gates
- audit log entries for plan / run / deny / complete events
- dry-run support
- workspace-rooted output paths

The engine never imports from any CLI module, so the same engine can be
driven from Typer, a Python script, or future automation. The CLI is just
one consumer.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime

from ..exceptions import (
    ConfirmationDeniedError,
    DrakeXError,
    OutOfScopeError,
)
from ..logging import get_logger
from ..models.artifact import Artifact
from ..models.finding import Finding
from ..models.scope import ScopeFile
from ..models.session import Session
from ..models.target import Target
from ..models.tool_result import ToolResult, ToolResultStatus
from ..normalize import normalize_result
from ..normalize.headers import audit_security_headers
from ..safety.confirm import ConfirmGate
from ..safety.enforcer import ScopeEnforcer
from ..safety.policy import ActionPolicy, PolicyClassifier
from ..utils.timefmt import utcnow
from .audit import AuditEvent, AuditLog
from .plugin_loader import PluginLoader, ToolEntry
from .rate_limit import RateLimiter
from .storage import WorkspaceStorage
from .workspace import Workspace

log = get_logger("engine")


@dataclass
class EnginePlan:
    """A pre-execution plan: what *would* run, given the current scope/policy."""

    target: Target
    profile: str
    eligible: list[ToolEntry]
    missing: list[ToolEntry]
    denied_by_policy: list[tuple[ToolEntry, str]]
    requires_confirmation: list[ToolEntry]


@dataclass
class EngineReport:
    """The complete output of one engine run."""

    session: Session
    tool_results: list[ToolResult]
    artifacts: list[Artifact]
    findings: list[Finding]
    plan: EnginePlan


class Engine:
    """Drake-X workspace-aware execution engine."""

    def __init__(
        self,
        *,
        workspace: Workspace,
        scope: ScopeFile,
        loader: PluginLoader,
        storage: WorkspaceStorage,
        ai=None,                                # AIAnalyzer | None
        confirm: ConfirmGate | None = None,
        actor: str = "operator",
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.workspace = workspace
        self.scope = scope
        self.loader = loader
        self.storage = storage
        self.ai = ai
        self.confirm = confirm or ConfirmGate()
        self.actor = actor
        self.enforcer = ScopeEnforcer(scope)
        self.policy = PolicyClassifier(scope)
        self.audit = AuditLog(workspace.audit_log_path)
        # Build a default rate limiter from the engagement scope. Callers
        # may inject a custom one (or a recording stub for tests). The
        # limiter is consulted only by integrations whose ``ToolMeta.http_style``
        # is True — non-HTTP tools (nmap, dig, whois) bypass it entirely.
        self.rate_limiter = rate_limiter or RateLimiter(
            max_concurrency=scope.max_concurrency,
            per_host_rps=scope.rate_limit_per_host_rps,
        )

    # ----- public API --------------------------------------------------

    def plan(self, *, target: Target, profile: str) -> EnginePlan:
        """Build an execution plan without running anything."""
        decision = self.enforcer.check_target(target)
        if not decision.allowed:
            self._audit("plan", target, decision="deny", payload={"reason": decision.reason})
            raise OutOfScopeError(decision.reason)

        eligible, missing = self.loader.select_for(profile=profile, target=target)

        denied: list[tuple[ToolEntry, str]] = []
        confirm_needed: list[ToolEntry] = []
        runnable: list[ToolEntry] = []

        for entry in eligible:
            policy_decision = self.policy.decide(entry.name)
            if not policy_decision.allowed:
                denied.append((entry, policy_decision.reason))
                continue
            if policy_decision.requires_confirmation:
                confirm_needed.append(entry)
            runnable.append(entry)

        plan = EnginePlan(
            target=target,
            profile=profile,
            eligible=runnable,
            missing=missing,
            denied_by_policy=denied,
            requires_confirmation=confirm_needed,
        )
        self._audit(
            "plan",
            target,
            decision="allow",
            payload={
                "profile": profile,
                "eligible": [e.name for e in runnable],
                "missing": [e.name for e in missing],
                "denied_by_policy": [{"name": n.name, "reason": r} for n, r in denied],
                "requires_confirmation": [e.name for e in confirm_needed],
            },
        )
        return plan

    async def run(
        self,
        plan: EnginePlan,
        *,
        dry_run: bool = False,
        ai_enabled: bool = False,
        tool_timeout: int | None = None,
    ) -> EngineReport:
        """Execute a plan. ``dry_run=True`` writes audit + manifest only."""
        timeout = tool_timeout or self.workspace.config.default_timeout

        session = Session(
            target=plan.target,
            profile=plan.profile,
            tools_planned=[e.name for e in plan.eligible],
            tools_skipped=[e.name for e in plan.missing],
            ai_enabled=ai_enabled and self.ai is not None,
            ai_model=self.ai.model_name if (ai_enabled and self.ai is not None) else None,
        )
        for m in plan.missing:
            session.warnings.append(f"tool {m.name!r} skipped: not installed")
        for entry, reason in plan.denied_by_policy:
            session.warnings.append(
                f"tool {entry.name!r} denied by policy: {reason}"
            )

        # Persist the session row first so the scope_assets foreign key has
        # something to point at, then snapshot the scope. Even a failed run
        # leaves an audit-quality copy of the engagement scope behind.
        self.storage.legacy.save_session(session)
        self.storage.save_scope_snapshot(session.id, self.scope)

        if dry_run:
            session.mark_finished(partial=True)
            session.warnings.append("dry-run: no tools were executed")
            self.storage.legacy.save_session(session)
            self._audit(
                "dry_run",
                plan.target,
                decision="allow",
                dry_run=True,
                session_id=session.id,
                payload={"planned": [e.name for e in plan.eligible]},
            )
            return EngineReport(
                session=session, tool_results=[], artifacts=[], findings=[], plan=plan
            )

        # Confirmation gate for active modules.
        for entry in plan.requires_confirmation:
            try:
                self.confirm.require(
                    action=entry.name,
                    target=plan.target.canonical,
                    policy=self.policy.classify(entry.name).value,
                )
            except ConfirmationDeniedError as exc:
                self._audit(
                    "confirm",
                    plan.target,
                    decision="deny",
                    session_id=session.id,
                    payload={"integration": entry.name, "reason": str(exc)},
                )
                session.warnings.append(
                    f"tool {entry.name!r} skipped: confirmation denied"
                )
                # remove this entry from eligible so we don't try to run it
                plan.eligible = [e for e in plan.eligible if e.name != entry.name]

        session.mark_running()
        self.storage.legacy.save_session(session)
        self._audit("run.start", plan.target, session_id=session.id)

        if not plan.eligible:
            session.warnings.append(
                "no eligible tools to run for this profile/target combination"
            )
            session.mark_finished(partial=True)
            self.storage.legacy.save_session(session)
            self._audit(
                "run.finish",
                plan.target,
                session_id=session.id,
                payload={"status": session.status.value},
            )
            return EngineReport(
                session=session, tool_results=[], artifacts=[], findings=[], plan=plan
            )

        # Split eligible tools into parallel-safe and serial buckets,
        # mirroring the v1 orchestrator's behavior.
        parallel = [e for e in plan.eligible if e.cls.meta.parallel_safe]
        serial = [e for e in plan.eligible if not e.cls.meta.parallel_safe]

        results: list[ToolResult] = []
        if parallel:
            results.extend(await self._run_parallel(parallel, plan.target, timeout))
        for entry in serial:
            results.append(await self._run_one(entry, plan.target, timeout))

        for r in results:
            self.storage.legacy.save_tool_result(session.id, r)
            if r.ran:
                session.tools_ran.append(r.tool_name)
                if r.status == ToolResultStatus.NONZERO:
                    session.warnings.append(
                        f"tool {r.tool_name!r} exited non-zero "
                        f"(exit_code={r.exit_code}); artifact is degraded"
                    )
            elif r.status == ToolResultStatus.NOT_INSTALLED:
                if r.tool_name not in session.tools_skipped:
                    session.tools_skipped.append(r.tool_name)
            elif r.status == ToolResultStatus.TIMEOUT:
                session.warnings.append(
                    f"tool {r.tool_name!r} timed out after {timeout}s"
                )
            elif r.status == ToolResultStatus.ERROR:
                session.warnings.append(
                    f"tool {r.tool_name!r} errored: {r.error_message}"
                )

        artifacts: list[Artifact] = []
        for r in results:
            artifact = normalize_result(r)
            if artifact is None:
                continue
            artifacts.append(artifact)
            self.storage.legacy.save_artifact(session.id, artifact)

        findings: list[Finding] = []

        # Rule-based findings layer (deterministic, no AI required).
        # The header audit reads curl + httpx artifacts and produces
        # Findings for missing/weak security controls. Failures here must
        # never break a scan, so we wrap the call defensively.
        try:
            header_findings = audit_security_headers(artifacts)
        except Exception as exc:  # noqa: BLE001 — defensive
            log.warning("header audit failed: %s", exc)
            session.warnings.append(f"header audit failed: {exc}")
            header_findings = []
        for f in header_findings:
            findings.append(f)
            try:
                self.storage.save_finding(session.id, f)
            except Exception as exc:  # noqa: BLE001 — persistence is best-effort here
                log.warning("failed to persist header finding %s: %s", f.id, exc)

        if session.ai_enabled and self.ai is not None:
            try:
                ai_findings, summary = await self.ai.analyze(
                    target=plan.target, profile=plan.profile, artifacts=artifacts
                )
                findings.extend(ai_findings)
                session.ai_summary = summary
                for f in ai_findings:
                    self.storage.save_finding(session.id, f)
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
        self.storage.legacy.save_session(session)
        self._audit(
            "run.finish",
            plan.target,
            session_id=session.id,
            payload={
                "status": session.status.value,
                "tools_ran": session.tools_ran,
                "warnings": session.warnings,
            },
        )
        return EngineReport(
            session=session,
            tool_results=results,
            artifacts=artifacts,
            findings=findings,
            plan=plan,
        )

    # ----- internals ---------------------------------------------------

    async def _run_one(
        self, entry: ToolEntry, target: Target, timeout: int
    ) -> ToolResult:
        started = utcnow()
        try:
            tool = self.loader.instantiate(entry)
            # HTTP-style integrations opt into the global concurrency
            # budget + per-host pacing exposed by the rate limiter. Other
            # integrations (nmap, dig, whois) bypass it entirely so the
            # limiter never throttles non-HTTP work.
            if entry.cls.meta.http_style and self.rate_limiter is not None:
                async with self.rate_limiter.slot(target.host):
                    return await tool.run(target, timeout=timeout)
            return await tool.run(target, timeout=timeout)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            log.exception("tool wrapper for %s raised unexpectedly", entry.name)
            finished = utcnow()
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
        tasks = [self._run_one(e, target, timeout) for e in entries]
        raw = await asyncio.gather(*tasks, return_exceptions=True)
        results: list[ToolResult] = []
        now = utcnow()
        for entry, item in zip(entries, raw, strict=True):
            if isinstance(item, BaseException):
                if isinstance(item, asyncio.CancelledError):
                    raise item
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

    def _audit(
        self,
        action: str,
        target: Target,
        *,
        decision: str = "allow",
        dry_run: bool = False,
        session_id: str | None = None,
        payload: dict | None = None,
    ) -> None:
        try:
            event = AuditEvent.now(
                actor=self.actor,
                action=action,
                subject=target.canonical,
                decision=decision,
                dry_run=dry_run,
                workspace=self.workspace.name,
                session_id=session_id,
                payload=payload,
            )
            self.audit.write(event)
        except Exception as exc:  # noqa: BLE001 — audit must never crash a run
            log.warning("audit log write failed: %s", exc)
