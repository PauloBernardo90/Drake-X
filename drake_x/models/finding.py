"""AI-, parser- or operator-generated finding.

A finding is **interpretation** rather than fact. It is meant to draw an
analyst's attention to something the model, a parser or a heuristic thought
worth a closer look. Findings always carry a clear ``source`` and a
``fact_or_inference`` flag so consumers can tell parser facts apart from LLM
guesses, and a list of :class:`FindingEvidence` references back into the
artifacts that produced them.

The model is intentionally extended (but backward compatible with v1
findings produced by the old AI analyzer) so that we can attach CWE / OWASP
/ MITRE ATT&CK references and a remediation placeholder for the report
writer.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from ..utils.ids import new_finding_id


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingSource(StrEnum):
    PARSER = "parser"      # deterministic, derived from a normalizer
    AI = "ai"              # produced by the local LLM
    RULE = "rule"          # produced by a static heuristic in code
    OPERATOR = "operator"  # added or annotated manually by the operator


class FindingEvidence(BaseModel):
    """A pointer back to the artifact that justifies a finding."""

    model_config = ConfigDict(frozen=True)

    artifact_kind: str
    tool_name: str
    excerpt: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class Finding(BaseModel):
    """A single observation worth a human's attention."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(default_factory=new_finding_id)
    title: str
    summary: str
    severity: FindingSeverity = FindingSeverity.INFO
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: FindingSource = FindingSource.PARSER
    fact_or_inference: Literal["fact", "inference"] = "fact"

    related_tools: list[str] = Field(default_factory=list)
    evidence: list[FindingEvidence] = Field(default_factory=list)

    cwe: list[str] = Field(
        default_factory=list,
        description="Optional list of CWE identifiers (e.g. ['CWE-200']).",
    )
    owasp: list[str] = Field(
        default_factory=list,
        description="Optional list of OWASP categories (e.g. ['A05:2021']).",
    )
    mitre_attck: list[str] = Field(
        default_factory=list,
        description="Optional list of MITRE ATT&CK technique IDs.",
    )

    recommended_next_steps: list[str] = Field(default_factory=list)
    remediation: str | None = Field(
        default=None,
        description="Free-text remediation placeholder for report drafts.",
    )
    caveats: list[str] = Field(default_factory=list)
    tags: list[str] = Field(
        default_factory=list,
        description="Operator-applied tags such as 'triaged', 'false-positive'.",
    )
