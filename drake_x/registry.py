"""Tool registry.

The registry knows which tool classes exist, whether their binaries are
installed, and which tools are eligible for a given (profile, target) pair.
The orchestrator asks the registry for an execution plan; it does not poke
at individual tool classes directly.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models.target import Target
from .tools import ALL_TOOLS, BaseTool


@dataclass(frozen=True)
class ToolEntry:
    """A registry row describing one supported tool."""

    name: str
    binary: str
    description: str
    profiles: tuple[str, ...]
    target_types: tuple[str, ...]
    installed: bool
    cls: type[BaseTool]


class ToolRegistry:
    """Discovers and selects tools."""

    def __init__(self, *, default_timeout: int) -> None:
        self.default_timeout = default_timeout
        self._entries: list[ToolEntry] = [self._make_entry(cls) for cls in ALL_TOOLS]

    @staticmethod
    def _make_entry(cls: type[BaseTool]) -> ToolEntry:
        meta = cls.meta
        return ToolEntry(
            name=meta.name,
            binary=meta.binary,
            description=meta.description,
            profiles=meta.profiles,
            target_types=meta.target_types,
            installed=cls.is_available(),
            cls=cls,
        )

    # ----- queries -----------------------------------------------------

    def all_entries(self) -> list[ToolEntry]:
        return list(self._entries)

    def get(self, name: str) -> ToolEntry | None:
        for e in self._entries:
            if e.name == name:
                return e
        return None

    def select_for(self, *, profile: str, target: Target) -> tuple[list[ToolEntry], list[ToolEntry]]:
        """Return ``(eligible, missing)`` tool entries for a given run.

        ``eligible`` are tools that match the profile/target AND are installed.
        ``missing`` are tools that would have matched but whose binary is
        absent on the host. Both lists are returned so the orchestrator can
        report skipped tools cleanly.
        """

        eligible: list[ToolEntry] = []
        missing: list[ToolEntry] = []
        for e in self._entries:
            if profile not in e.profiles:
                continue
            if target.target_type not in e.target_types:
                continue
            if e.installed:
                eligible.append(e)
            else:
                missing.append(e)
        return eligible, missing

    def instantiate(self, entry: ToolEntry) -> BaseTool:
        return entry.cls(default_timeout=self.default_timeout)

    # ----- maintenance -------------------------------------------------

    def refresh_availability(self) -> None:
        """Re-check installed status for every tool. Useful in long-running tests."""
        self._entries = [self._make_entry(e.cls) for e in self._entries]
