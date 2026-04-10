"""Prompts for the local Ollama analyst.

The system prompt is intentionally narrow:

- the model is a *defensive* recon analyst
- it must summarize only what's in the evidence
- it must label observations vs inferences
- it must NEVER suggest exploitation, payloads, or post-exploitation steps
- output is a strict JSON object so we can parse it deterministically
"""

from __future__ import annotations

import json
from typing import Any

ANALYST_SYSTEM_PROMPT = """You are Drake-X, a careful DEFENSIVE reconnaissance
analyst. You receive structured evidence collected by passive and safe active
recon tools (nmap, dig, whois, whatweb, nikto information-only mode, curl,
sslscan) and you must produce a brief triage for a human analyst.

Hard constraints — never violate:

1. You MUST only summarize information present in the evidence. Do not invent
   ports, services, vulnerabilities, hostnames, or technologies.
2. You MUST clearly distinguish OBSERVATIONS (in the evidence) from
   INFERENCES (your reasoning).
3. You MUST NOT suggest, hint at, or describe exploitation, payloads,
   credential attacks, brute forcing, privilege escalation, persistence,
   lateral movement, phishing, or any post-exploitation activity.
4. Recommended next steps must be SAFE recon-only actions (e.g. "review TLS
   policy", "confirm ownership of subdomain in WHOIS", "request DNSSEC
   status from the domain owner").
5. Each evidence item carries ``tool_status``, ``exit_code``, and ``degraded``
   fields. When ``degraded`` is true the underlying tool did not finish
   cleanly and the parsed payload may be incomplete — lower your confidence
   accordingly and call this out in the caveats.
6. Be cautious. When the evidence is thin, lower your confidence and say so.
7. Reply with a single JSON object matching the schema you are given. No
   extra commentary, no markdown fences.
"""


OUTPUT_SCHEMA: dict[str, Any] = {
    "executive_summary": "string",
    "notable_observations": ["string"],
    "potential_risk_signals": ["string"],
    "confidence": "low | medium | high",
    "recommended_next_safe_steps": ["string"],
    "caveats": ["string"],
}


def build_analyst_prompt(*, target_display: str, profile: str, evidence: list[dict[str, Any]]) -> str:
    """Build the user prompt sent to Ollama."""

    schema_text = json.dumps(OUTPUT_SCHEMA, indent=2)
    # Hard cap the evidence size so we never blow the context budget on a
    # noisy scan. Sorted by tool name so output is deterministic in tests.
    trimmed = [_trim_artifact(a) for a in evidence][:8]
    evidence_text = json.dumps(trimmed, indent=2, default=str)

    return f"""TARGET: {target_display}
PROFILE: {profile}

EVIDENCE (parsed artifacts from local recon tools):
{evidence_text}

OUTPUT SCHEMA (return one JSON object exactly matching these keys):
{schema_text}

Reminder: defensive recon only. No exploitation suggestions.
Return ONLY the JSON object.
"""


def _trim_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    """Reduce a serialized artifact to fields the model needs.

    Execution provenance (``tool_status``, ``exit_code``, ``degraded``) is
    included so the model can tell a clean run from a degraded one and
    moderate its claims accordingly.
    """
    return {
        "tool": artifact.get("tool_name"),
        "kind": artifact.get("kind"),
        "confidence": artifact.get("confidence"),
        "tool_status": artifact.get("tool_status", "ok"),
        "exit_code": artifact.get("exit_code"),
        "degraded": bool(artifact.get("degraded", False)),
        "payload": _truncate_payload(artifact.get("payload", {})),
        "notes": artifact.get("notes", []),
    }


def _truncate_payload(payload: Any, *, max_chars: int = 800) -> Any:
    text = json.dumps(payload, default=str)
    if len(text) <= max_chars:
        return payload
    return {"_truncated": True, "_excerpt": text[:max_chars]}
