"""Local-LLM task modules.

Each task is a small object with:

- a name
- a JSON schema the model must satisfy
- a prompt template loaded from ``prompts/`` on disk
- a deterministic-by-default temperature
- a maximum evidence-budget so we never blow the model's context

Tasks never invoke tools. They take artifacts/findings as input and return
either a structured result or ``None`` (degraded gracefully).
"""

from .apk_assessment import ApkAssessmentTask
from .apk_campaign import ApkCampaignTask
from .apk_obfuscation import ApkObfuscationTask
from .dex_assessment import DexAssessmentTask
from .assist_suggest import AssistSuggestTask
from .base import AITask, AITaskResult, TaskContext
from .classify import ClassifyTask
from .dedupe import DedupeTask
from .next_steps import NextStepsTask
from .observations import ObservationsTask
from .report_draft import ReportDraftTask
from .summarize import SummarizeTask

ALL_TASKS = (
    SummarizeTask,
    ClassifyTask,
    NextStepsTask,
    ObservationsTask,
    ReportDraftTask,
    DedupeTask,
    ApkAssessmentTask,
    ApkObfuscationTask,
    ApkCampaignTask,
    DexAssessmentTask,
    AssistSuggestTask,
)

__all__ = [
    "AITask",
    "AITaskResult",
    "TaskContext",
    "SummarizeTask",
    "ClassifyTask",
    "DedupeTask",
    "NextStepsTask",
    "ObservationsTask",
    "ReportDraftTask",
    "ApkAssessmentTask",
    "ApkObfuscationTask",
    "ApkCampaignTask",
    "DexAssessmentTask",
    "AssistSuggestTask",
    "ALL_TASKS",
]
