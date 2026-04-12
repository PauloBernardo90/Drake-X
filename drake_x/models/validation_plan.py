"""Multi-domain structured validation plan (v1.0).

Drake-X has accumulated several ad-hoc validation surfaces:

- APK Frida target suggestions
- PE "dynamic analysis required" recommendations
- Native analysis follow-ups
- AI-task ``dynamic_validation_needed`` fields

v1.0 unifies them behind one persistent model. A validation plan is
a structured checklist analysts can work from, track status against,
and export. It is domain-agnostic so a case spanning APK + PE has a
single plan.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PlanStatus(StrEnum):
    PLANNED = "planned"
    EXECUTED = "executed"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class Priority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


Domain = Literal["pe", "apk", "elf", "native", "external", "case"]


class ValidationItem(BaseModel):
    """One validation step."""

    model_config = ConfigDict(frozen=True)

    item_id: str
    domain: Domain
    hypothesis: str = Field(description="What we believe and want to confirm.")
    rationale: str = Field(description="Why this hypothesis is plausible.")
    suggested_steps: list[str] = Field(default_factory=list)
    expected_evidence: str = ""
    suggested_tool: str = ""
    priority: Priority = Priority.MEDIUM
    status: PlanStatus = PlanStatus.PLANNED
    evidence_node_ids: list[str] = Field(
        default_factory=list,
        description="Graph node IDs backing the hypothesis.",
    )
    result_evidence_node_ids: list[str] = Field(
        default_factory=list,
        description="Graph node IDs produced by executing this step (post-execution).",
    )


class ValidationPlan(BaseModel):
    """A persistent, multi-domain validation plan."""

    model_config = ConfigDict(frozen=True)

    session_id: str
    items: list[ValidationItem] = Field(default_factory=list)
    caveats: list[str] = Field(
        default_factory=lambda: [
            "plan items are analyst-assisted suggestions, not executable commands",
            "executing a step requires operator review; Drake-X does not run it automatically",
        ],
    )
