"""Release-gate: Drake-X version metadata must stay consistent.

The previous v0.9.0 → v0.9.1 bump surfaced a drift risk: three separate
call sites embedded the version string. This test is the standing
guard against that class of bug — any future release bump must update
all surfaces together.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import drake_x
from drake_x.models.pe import PeAnalysisResult, PeMetadata, ExploitIndicator, ExploitIndicatorType
from drake_x.reporting.detection_writer import render_pe_stix_bundle


REPO_ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    # First occurrence of top-level ``version = "…"`` in the [project] table.
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert m is not None, "could not parse version out of pyproject.toml"
    return m.group(1)


def test_package_version_matches_pyproject():
    assert drake_x.__version__ == _pyproject_version(), (
        f"drake_x.__version__ ({drake_x.__version__}) does not match "
        f"pyproject.toml version ({_pyproject_version()}). Bump both "
        "in the same commit."
    )


def test_stix_generator_version_matches_package():
    """STIX bundles embed ``x_drake_x.generator_version``. It must come
    from drake_x.__version__ so a version bump cannot silently leave
    STIX output reporting a stale version.
    """
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256="v" * 64),
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="t", description="d",
                severity="high", confidence=0.8,
                evidence_refs=["VirtualAllocEx"],
            ),
        ],
    )
    bundle = json.loads(render_pe_stix_bundle(r))
    assert bundle["x_drake_x"]["generator_version"] == drake_x.__version__


def test_cli_banner_reflects_package_version():
    from typer.testing import CliRunner
    from drake_x.cli import app

    r = CliRunner().invoke(app, ["--help"], env={"COLUMNS": "240"})
    assert r.exit_code == 0
    assert f"v{drake_x.__version__}" in r.output, (
        f"drake --help banner does not expose v{drake_x.__version__}"
    )
