"""Drake-X v0.2 reporting layer.

Each writer is independent so callers can mix and match (e.g. JSON +
executive Markdown for an executive recap, JSON + technical Markdown +
manifest for a full deliverable).

The legacy renderer at :mod:`drake_x.reports.markdown` is still imported by
v1 tests; new code should depend on :func:`render_markdown_report` here,
which is a thin wrapper that delegates to the v1 renderer for now and will
become the v2 implementation as the report grows new sections.
"""

from .evidence_index import build_evidence_index
from .executive_writer import render_executive_report
from .json_writer import render_json_report
from .manifest import build_scan_manifest
from .markdown_writer import render_markdown_report

__all__ = [
    "render_markdown_report",
    "render_executive_report",
    "render_json_report",
    "build_scan_manifest",
    "build_evidence_index",
]
