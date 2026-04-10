"""Top-level dispatch for tool result normalization.

The orchestrator hands one :class:`ToolResult` at a time to
:func:`normalize_result`, which routes it to the right per-tool normalizer.
Every normalizer is expected to be defensive: if it can't parse anything, it
should return a low-confidence artifact rather than raise.
"""

from __future__ import annotations

from collections.abc import Callable

from ..logging import get_logger
from ..models.artifact import Artifact
from ..models.tool_result import ToolResult, ToolResultStatus
from .dns import normalize_dig
from .ffuf import normalize_ffuf
from .httpx import normalize_httpx
from .nmap import normalize_nmap
from .web import normalize_curl, normalize_nikto, normalize_sslscan, normalize_whatweb
from .whois import normalize_whois

log = get_logger("normalize")

_REGISTRY: dict[str, Callable[[ToolResult], Artifact | None]] = {
    "nmap": normalize_nmap,
    "dig": normalize_dig,
    "whois": normalize_whois,
    "whatweb": normalize_whatweb,
    "nikto": normalize_nikto,
    "curl": normalize_curl,
    "sslscan": normalize_sslscan,
    "httpx": normalize_httpx,
    "ffuf": normalize_ffuf,
}


_DEGRADED_CONFIDENCE_FACTOR = 0.5


def normalize_result(result: ToolResult) -> Artifact | None:
    """Normalize a single tool result.

    Returns ``None`` for results that have nothing useful to parse (e.g. the
    tool was not installed or it errored before producing any output).

    Non-zero exits ARE still parsed when stdout looks usable, but the resulting
    artifact is decorated with execution provenance and explicitly marked as
    ``degraded``. Confidence is multiplied by a conservative factor so the
    artifact is never confused with a clean run downstream.
    """

    if result.status in {ToolResultStatus.NOT_INSTALLED, ToolResultStatus.ERROR}:
        return None
    if result.status == ToolResultStatus.TIMEOUT and not result.stdout:
        return None
    # Non-zero exits with no stdout at all carry no signal worth surfacing.
    if result.status == ToolResultStatus.NONZERO and not result.stdout.strip():
        return None

    fn = _REGISTRY.get(result.tool_name)
    if fn is None:
        log.debug("no normalizer registered for %s", result.tool_name)
        return None

    try:
        artifact = fn(result)
    except Exception as exc:  # noqa: BLE001 — defensive: parsing must not crash a scan
        log.warning(
            "normalizer for %s raised %s; producing fallback artifact",
            result.tool_name,
            exc,
        )
        artifact = Artifact(
            tool_name=result.tool_name,
            kind=f"{result.tool_name}.unparsed",
            payload={"error": str(exc)},
            confidence=0.0,
            notes=["normalizer raised an exception"],
            raw_command=result.command,
            raw_stdout_excerpt=result.stdout[:1000] if result.stdout else None,
        )

    return _decorate_with_provenance(artifact, result)


def _decorate_with_provenance(artifact: Artifact, result: ToolResult) -> Artifact:
    """Stamp execution provenance onto an artifact and degrade non-clean runs."""

    degraded = result.status != ToolResultStatus.OK
    notes = list(artifact.notes)
    confidence = artifact.confidence

    if degraded:
        confidence = round(confidence * _DEGRADED_CONFIDENCE_FACTOR, 4)
        suffix = (
            f"degraded execution: tool exited with status={result.status.value}"
            + (f" (exit_code={result.exit_code})" if result.exit_code is not None else "")
            + " — confidence reduced and the artifact may be incomplete"
        )
        notes.append(suffix)

    return artifact.model_copy(
        update={
            "tool_status": result.status.value,
            "exit_code": result.exit_code,
            "degraded": degraded,
            "confidence": confidence,
            "notes": notes,
        }
    )
