"""AI-generated or rule-based finding.

A finding is **interpretation** rather than fact. It is meant to draw an
analyst's attention to something the model or a parser thought worth a closer
look. Findings always carry a clear ``source`` so consumers can tell parser
output apart from LLM output.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingSource(StrEnum):
    PARSER = "parser"      # deterministic, derived from a normalizer
    AI = "ai"              # produced by the local LLM
    RULE = "rule"          # produced by a static heuristic in code


class Finding(BaseModel):
    """A single observation worth a human's attention."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    title: str
    summary: str
    severity: FindingSeverity = FindingSeverity.INFO
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: FindingSource = FindingSource.PARSER
    related_tools: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)
