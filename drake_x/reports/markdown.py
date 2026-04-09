"""Markdown report renderer.

Plain string templating — no Jinja2 needed for this much structure. The
report is intentionally cautious in tone: every interpretive bullet point
is labeled as analyst-validation-required.
"""

from __future__ import annotations

from typing import Any

from ..constants import AUTHORIZED_USE_NOTICE
from ..models.artifact import Artifact
from ..models.finding import Finding
from ..models.session import Session
from ..models.tool_result import ToolResult


def render_markdown_report(
    *,
    session: Session,
    tool_results: list[ToolResult],
    artifacts: list[Artifact],
    findings: list[Finding],
) -> str:
    lines: list[str] = []
    lines.append(f"# Drake-X Recon Report — `{session.id}`")
    lines.append("")
    lines.append(f"> {AUTHORIZED_USE_NOTICE}")
    lines.append("")

    # ----- session metadata --------------------------------------------
    lines.append("## Session metadata")
    lines.append("")
    lines.append(f"- **Session ID:** `{session.id}`")
    lines.append(f"- **Profile:** `{session.profile}`")
    lines.append(f"- **Status:** `{session.status.value}`")
    lines.append(f"- **Started:** {session.started_at.isoformat()}")
    if session.finished_at:
        lines.append(f"- **Finished:** {session.finished_at.isoformat()}")
        if session.duration_seconds is not None:
            lines.append(f"- **Duration:** {session.duration_seconds:.1f}s")
    lines.append("")

    # ----- target ------------------------------------------------------
    t = session.target
    lines.append("## Target")
    lines.append("")
    lines.append(f"- **Raw input:** `{t.raw}`")
    lines.append(f"- **Canonical:** `{t.canonical}`")
    lines.append(f"- **Type:** `{t.target_type}`")
    lines.append(f"- **Host:** `{t.host}`")
    if t.cidr_prefix is not None:
        lines.append(f"- **Prefix length:** /{t.cidr_prefix}")
    if t.url_scheme:
        lines.append(f"- **URL scheme:** `{t.url_scheme}`")
        if t.url_port:
            lines.append(f"- **URL port:** `{t.url_port}`")
        if t.url_path:
            lines.append(f"- **URL path:** `{t.url_path}`")
    lines.append("")

    # ----- tools -------------------------------------------------------
    lines.append("## Tools")
    lines.append("")
    lines.append(f"- **Planned:** {_inline(session.tools_planned)}")
    lines.append(f"- **Ran:** {_inline(session.tools_ran)}")
    lines.append(f"- **Skipped / missing:** {_inline(session.tools_skipped)}")
    if session.warnings:
        lines.append("- **Warnings:**")
        for w in session.warnings:
            lines.append(f"    - {w}")
    lines.append("")

    if tool_results:
        lines.append("### Per-tool execution summary")
        lines.append("")
        lines.append("| Tool | Status | Exit | Duration | Notes |")
        lines.append("|------|--------|------|----------|-------|")
        for r in tool_results:
            duration = f"{r.duration_seconds:.1f}s" if r.duration_seconds is not None else "—"
            note = (r.error_message or "").splitlines()[0] if r.error_message else ""
            lines.append(
                f"| `{r.tool_name}` | `{r.status.value}` | `{r.exit_code}` | {duration} | {note} |"
            )
        lines.append("")

        degraded = [a for a in artifacts if a.degraded]
        if degraded:
            lines.append(
                "> ⚠ Some artifacts below were derived from a **degraded** tool "
                "execution (non-zero exit, timeout, or parser fallback). They are "
                "explicitly flagged inline and confidence is reduced."
            )
            lines.append("")

    # ----- artifacts ---------------------------------------------------
    if artifacts:
        lines.append("## Observations")
        lines.append("")

        nmap_artifacts = [a for a in artifacts if a.tool_name == "nmap"]
        dns_artifacts = [a for a in artifacts if a.tool_name == "dig"]
        whois_artifacts = [a for a in artifacts if a.tool_name == "whois"]
        web_fp = [a for a in artifacts if a.tool_name == "whatweb"]
        web_meta = [a for a in artifacts if a.tool_name == "curl"]
        nikto_artifacts = [a for a in artifacts if a.tool_name == "nikto"]
        tls_artifacts = [a for a in artifacts if a.tool_name == "sslscan"]

        if nmap_artifacts:
            lines.append("### Discovered services (nmap)")
            lines.append("")
            for art in nmap_artifacts:
                _emit_provenance(lines, art)
                _render_nmap(lines, art.payload)
            lines.append("")

        if dns_artifacts:
            lines.append("### DNS records")
            lines.append("")
            for art in dns_artifacts:
                _emit_provenance(lines, art)
                _render_dns(lines, art.payload)
            lines.append("")

        if whois_artifacts:
            lines.append("### WHOIS summary")
            lines.append("")
            for art in whois_artifacts:
                _emit_provenance(lines, art)
                _render_whois(lines, art.payload)
            lines.append("")

        if web_fp or web_meta:
            lines.append("### Web stack observations")
            lines.append("")
            for art in web_fp:
                _emit_provenance(lines, art)
                _render_whatweb(lines, art.payload)
            for art in web_meta:
                _emit_provenance(lines, art)
                _render_curl(lines, art.payload)
            lines.append("")

        if nikto_artifacts:
            lines.append("### Web posture (nikto, information-only)")
            lines.append("")
            for art in nikto_artifacts:
                _emit_provenance(lines, art)
                _render_nikto(lines, art.payload, art.notes)
            lines.append("")

        if tls_artifacts:
            lines.append("### TLS observations")
            lines.append("")
            for art in tls_artifacts:
                _emit_provenance(lines, art)
                _render_sslscan(lines, art.payload)
            lines.append("")

    # ----- AI / findings ----------------------------------------------
    if session.ai_enabled and (session.ai_summary or findings):
        lines.append("## AI triage (local Ollama)")
        lines.append("")
        if session.ai_model:
            lines.append(f"_Model:_ `{session.ai_model}`")
            lines.append("")
        if session.ai_summary:
            lines.append("**Executive summary**")
            lines.append("")
            lines.append(session.ai_summary)
            lines.append("")
        if findings:
            lines.append("**Findings**")
            lines.append("")
            for f in findings:
                lines.append(f"- **[{f.severity.value}] {f.title}** _(confidence {f.confidence:.2f}, source `{f.source.value}`)_")
                lines.append(f"    - {f.summary}")
                if f.recommended_next_steps:
                    lines.append("    - Suggested safe next steps:")
                    for step in f.recommended_next_steps:
                        lines.append(f"        - {step}")
                if f.caveats:
                    lines.append("    - Caveats:")
                    for c in f.caveats:
                        lines.append(f"        - {c}")
            lines.append("")

    # ----- closing -----------------------------------------------------
    lines.append("## Analyst guidance")
    lines.append("")
    lines.append(
        "All observations above are produced by automated tooling and parsers. "
        "They MUST be validated by a human analyst before being treated as "
        "authoritative. Drake-X intentionally limits itself to safe reconnaissance "
        "and does not perform exploitation."
    )
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# ----- helpers --------------------------------------------------------------


def _inline(values: list[str]) -> str:
    if not values:
        return "_none_"
    return ", ".join(f"`{v}`" for v in values)


def _emit_provenance(lines: list[str], artifact: Artifact) -> None:
    """Emit a one-line provenance hint for a degraded artifact, otherwise nothing."""
    if not artifact.degraded:
        return
    exit_str = (
        f", exit_code={artifact.exit_code}" if artifact.exit_code is not None else ""
    )
    lines.append(
        f"_⚠ degraded execution — tool_status=`{artifact.tool_status}`{exit_str}, "
        f"confidence={artifact.confidence:.2f}_"
    )


def _render_nmap(lines: list[str], payload: dict[str, Any]) -> None:
    hosts = payload.get("hosts", [])
    if not hosts:
        lines.append("_No hosts in nmap output._")
        return
    for host in hosts:
        addrs = ", ".join(a["addr"] for a in host.get("addresses", []))
        names = ", ".join(host.get("hostnames", []) or [])
        lines.append(f"- **Host:** `{addrs}`" + (f" ({names})" if names else "") + f" — status: `{host.get('status', '?')}`")
        ports = host.get("open_ports", [])
        if not ports:
            lines.append("    - _no open ports detected_")
            continue
        for p in ports:
            svc = p.get("service") or "?"
            product = p.get("product") or ""
            version = p.get("version") or ""
            extra = " ".join(x for x in [product, version] if x)
            extra_str = f" ({extra})" if extra else ""
            lines.append(f"    - `{p['port']}/{p.get('protocol', 'tcp')}` — {svc}{extra_str}")


def _render_dns(lines: list[str], payload: dict[str, Any]) -> None:
    records = payload.get("records", {})
    if not records:
        lines.append("_No DNS records parsed._")
        return
    for rtype, values in records.items():
        lines.append(f"- **{rtype}**")
        for v in values:
            lines.append(f"    - `{v}`")


def _render_whois(lines: list[str], payload: dict[str, Any]) -> None:
    if not payload:
        lines.append("_WHOIS output could not be parsed into known fields._")
        return
    for key in ("registrar", "org", "country", "creation_date", "updated_date", "expiration_date"):
        if key in payload:
            lines.append(f"- **{key.replace('_', ' ').title()}:** `{payload[key]}`")
    if "nameservers" in payload:
        lines.append("- **Nameservers:**")
        for ns in payload["nameservers"]:
            lines.append(f"    - `{ns}`")


def _render_whatweb(lines: list[str], payload: dict[str, Any]) -> None:
    techs = payload.get("technologies", [])
    if not techs:
        lines.append("_No technologies fingerprinted by whatweb._")
        return
    lines.append(f"- **Target:** `{payload.get('target', '?')}`")
    lines.append("- **Technologies / fingerprints:**")
    for t in techs:
        lines.append(f"    - `{t}`")


def _render_curl(lines: list[str], payload: dict[str, Any]) -> None:
    final_status = payload.get("final_status")
    headers = payload.get("final_headers", {}) or {}
    if final_status is None:
        lines.append("_curl produced no parseable HTTP response._")
        return
    lines.append(f"- **Final status:** `{final_status}`")
    interesting = ("server", "x-powered-by", "content-type", "strict-transport-security", "set-cookie")
    for h in interesting:
        if h in headers:
            lines.append(f"- **{h}:** `{headers[h]}`")
    chain = payload.get("redirect_chain", [])
    if chain:
        lines.append("- **Redirect chain:**")
        for url in chain:
            lines.append(f"    - `{url}`")


def _render_nikto(lines: list[str], payload: dict[str, Any], notes: list[str]) -> None:
    findings = payload.get("headline_findings", [])
    if not findings:
        lines.append("_No information-only nikto observations._")
    else:
        for f in findings:
            lines.append(f"- {f}")
    if payload.get("suppressed_exploit_suggestions"):
        lines.append(
            f"_Drake-X suppressed {payload['suppressed_exploit_suggestions']} nikto lines that "
            "looked like exploit suggestions._"
        )


def _render_sslscan(lines: list[str], payload: dict[str, Any]) -> None:
    enabled = payload.get("enabled_protocols", [])
    deprecated = payload.get("deprecated_enabled", [])
    weak = payload.get("weak_cipher_lines", [])
    cert = payload.get("certificate", {}) or {}
    if enabled:
        lines.append(f"- **Enabled protocols:** {', '.join(f'`{p}`' for p in enabled)}")
    if deprecated:
        lines.append(
            f"- **Deprecated protocols still enabled:** {', '.join(f'`{p}`' for p in deprecated)}"
        )
    if weak:
        lines.append("- **Weak cipher lines (information-only):**")
        for line in weak:
            lines.append(f"    - `{line}`")
    if cert:
        lines.append("- **Certificate:**")
        for k in ("subject", "issuer", "not_before", "not_after"):
            if k in cert:
                lines.append(f"    - **{k.replace('_', ' ').title()}:** `{cert[k]}`")
