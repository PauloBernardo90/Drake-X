"""Data models for IoC enrichment results."""

from __future__ import annotations

from pydantic import BaseModel, Field


class IocVtResult(BaseModel):
    """VT enrichment for one domain or IP."""

    indicator: str = ""
    indicator_type: str = ""  # "domain" or "ip"
    available: bool = False
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int | None = None
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    as_owner: str = ""
    last_modification_date: str = ""
    error: str | None = None
    source_label: str = "virustotal_v3_api"


class IocEnrichmentResult(BaseModel):
    """Collection of VT lookups for a session's indicators."""

    domain_results: list[IocVtResult] = Field(default_factory=list)
    ip_results: list[IocVtResult] = Field(default_factory=list)
    skipped: int = 0
    errors: int = 0
