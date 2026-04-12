"""Ingest adapter base + registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ...models.external_evidence import ExternalEvidenceRecord


_REGISTRY: dict[str, type["BaseIngestAdapter"]] = {}


def register(name: str):
    """Decorator: register an adapter class under *name*."""

    def _wrap(cls: type["BaseIngestAdapter"]):
        if name in _REGISTRY:
            raise ValueError(f"adapter '{name}' already registered")
        _REGISTRY[name] = cls
        cls.name = name
        return cls

    return _wrap


def adapter_registry() -> dict[str, type["BaseIngestAdapter"]]:
    """Return a defensive copy of the registry."""
    return dict(_REGISTRY)


class BaseIngestAdapter(ABC):
    """Base class for ingestion adapters.

    Subclasses override :meth:`parse`. The base class does nothing but
    define the contract — adapters MUST NOT invent data they do not
    have; they translate or skip.
    """

    name: str = "base"

    @abstractmethod
    def parse(
        self, path: Path, *, trust: str = "medium"
    ) -> list[ExternalEvidenceRecord]:
        """Parse *path* and return normalized external records."""
        ...
