"""Plugin loader.

Drake-X discovers integrations from two places:

1. The built-in adapters under :mod:`drake_x.tools` (the v1 list) and the
   new :mod:`drake_x.integrations.builtin` package — kept identical so the
   v1 registry/orchestrator and the v2 engine see the same code.
2. Third-party Python packages that register a ``drake_x.integrations``
   entry point pointing at a :class:`BaseTool` subclass.

The loader returns plain :class:`ToolEntry` records identical to the ones
the legacy registry produced, so existing call sites can switch over
without rewriting their query logic.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
from dataclasses import dataclass

from ..exceptions import PluginLoadError
from ..integrations.optional import OPTIONAL_REAL_TOOLS
from ..logging import get_logger
from ..models.target import Target
from ..tools import ALL_TOOLS, BaseTool

log = get_logger("plugin_loader")

ENTRY_POINT_GROUP = "drake_x.integrations"


@dataclass(frozen=True)
class ToolEntry:
    """A registry row describing one supported integration."""

    name: str
    binary: str
    description: str
    profiles: tuple[str, ...]
    target_types: tuple[str, ...]
    installed: bool
    cls: type[BaseTool]
    origin: str = "builtin"          # 'builtin' | 'entry_point'


class PluginLoader:
    """Discovers built-in and entry-point integrations."""

    def __init__(self, *, default_timeout: int) -> None:
        self.default_timeout = default_timeout
        self._entries: list[ToolEntry] = []
        self._loaded = False

    # ----- discovery ---------------------------------------------------

    def load(self) -> "PluginLoader":
        if self._loaded:
            return self
        builtins = [self._make_entry(cls, origin="builtin") for cls in ALL_TOOLS]
        # Real optional integrations (e.g. httpx) ship with Drake-X but
        # need an external binary to actually execute. The plugin loader
        # treats them like builtins for discovery purposes — the
        # ``installed`` flag tells the operator whether the binary is
        # actually present on the host.
        optional_real = [
            self._make_entry(cls, origin="optional") for cls in OPTIONAL_REAL_TOOLS
        ]
        entry_points = list(self._discover_entry_points())
        self._entries = builtins + optional_real + entry_points
        self._loaded = True
        return self

    def _discover_entry_points(self) -> list[ToolEntry]:
        out: list[ToolEntry] = []
        try:
            eps = importlib_metadata.entry_points(group=ENTRY_POINT_GROUP)
        except Exception as exc:  # noqa: BLE001
            log.debug("entry_points discovery failed: %s", exc)
            return out

        for ep in eps:
            try:
                cls = ep.load()
            except Exception as exc:  # noqa: BLE001
                log.warning("failed to load entry point %s: %s", ep.name, exc)
                continue
            if not isinstance(cls, type) or not issubclass(cls, BaseTool):
                log.warning(
                    "entry point %s does not point at a BaseTool subclass; skipping",
                    ep.name,
                )
                continue
            try:
                out.append(self._make_entry(cls, origin="entry_point"))
            except PluginLoadError as exc:
                log.warning("entry point %s rejected: %s", ep.name, exc)
        return out

    @staticmethod
    def _make_entry(cls: type[BaseTool], *, origin: str) -> ToolEntry:
        meta = getattr(cls, "meta", None)
        if meta is None:
            raise PluginLoadError(
                f"{cls.__name__} has no `meta` ToolMeta — cannot register"
            )
        return ToolEntry(
            name=meta.name,
            binary=meta.binary,
            description=meta.description,
            profiles=meta.profiles,
            target_types=meta.target_types,
            installed=cls.is_available(),
            cls=cls,
            origin=origin,
        )

    # ----- queries -----------------------------------------------------

    def all(self) -> list[ToolEntry]:
        self.load()
        return list(self._entries)

    def get(self, name: str) -> ToolEntry | None:
        self.load()
        for e in self._entries:
            if e.name == name:
                return e
        return None

    def select_for(
        self, *, profile: str, target: Target
    ) -> tuple[list[ToolEntry], list[ToolEntry]]:
        """Return ``(eligible, missing)`` for a given profile + target."""
        self.load()
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

    def refresh_availability(self) -> None:
        self.load()
        self._entries = [self._make_entry(e.cls, origin=e.origin) for e in self._entries]
