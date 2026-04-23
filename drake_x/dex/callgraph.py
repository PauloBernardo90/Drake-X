"""Call graph / relation graph builder for DEX analysis.

Produces a lightweight relation graph from call edges, class references,
and Android component declarations. The graph can be queried for:

- Method-to-method call chains
- Class-to-class references
- Component relationships (Activity/Service/Receiver linkage)
- Suspicious call paths (e.g., paths from entry points to sensitive APIs)
"""

from __future__ import annotations

from collections import defaultdict

from ..logging import get_logger
from ..models.dex import (
    CallEdge,
    DexClassInfo,
    SensitiveApiHit,
)

log = get_logger("dex.callgraph")


class DexCallGraph:
    """Lightweight directed graph of method/class relationships.

    Not a full-fidelity static analysis graph — it's a pragmatic
    approximation built from smali invoke instructions and class
    references.
    """

    def __init__(self) -> None:
        # method-level: (class, method) → set of (class, method)
        self._calls: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
        # class-level references
        self._class_refs: dict[str, set[str]] = defaultdict(set)
        # reverse index
        self._callers: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
        self._edges: list[CallEdge] = []

    @property
    def edges(self) -> list[CallEdge]:
        return list(self._edges)

    @property
    def method_count(self) -> int:
        return len(set(self._calls.keys()) | set(self._callers.keys()))

    @property
    def class_count(self) -> int:
        return len(set(self._class_refs.keys())
                    | {c for targets in self._class_refs.values() for c in targets})

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def add_edges(self, edges: list[CallEdge]) -> None:
        """Add call edges to the graph."""
        for edge in edges:
            caller = (edge.caller_class, edge.caller_method)
            callee = (edge.callee_class, edge.callee_method)
            self._calls[caller].add(callee)
            self._callers[callee].add(caller)
            self._class_refs[edge.caller_class].add(edge.callee_class)
            self._edges.append(edge)

    def add_class_references(self, classes: list[DexClassInfo]) -> None:
        """Add class hierarchy references (superclass, interfaces)."""
        for cls in classes:
            if cls.superclass:
                self._class_refs[cls.class_name].add(cls.superclass)
            for iface in cls.interfaces:
                self._class_refs[cls.class_name].add(iface)

    def callees_of(self, class_name: str, method_name: str) -> list[tuple[str, str]]:
        """Return direct callees of a method."""
        return sorted(self._calls.get((class_name, method_name), set()))

    def callers_of(self, class_name: str, method_name: str) -> list[tuple[str, str]]:
        """Return direct callers of a method."""
        return sorted(self._callers.get((class_name, method_name), set()))

    def classes_referenced_by(self, class_name: str) -> list[str]:
        """Return classes directly referenced by the given class."""
        return sorted(self._class_refs.get(class_name, set()))

    def find_paths_to_api(
        self,
        api_hits: list[SensitiveApiHit],
        entry_classes: list[str] | None = None,
        max_depth: int = 5,
    ) -> list[list[tuple[str, str]]]:
        """Find call paths from entry points to sensitive API usages.

        Parameters
        ----------
        api_hits:
            Detected sensitive API usages (used to identify target methods).
        entry_classes:
            Classes to start from (e.g., Activities, Services). If None,
            uses all classes that have no callers.
        max_depth:
            Maximum call chain depth to explore.

        Returns
        -------
        List of paths, where each path is a list of (class, method) tuples.
        """
        # Build set of target methods from API hits
        targets: set[str] = set()
        for hit in api_hits:
            targets.add(hit.api_name)
            if hit.class_name:
                targets.add(hit.class_name)

        if not targets:
            return []

        # Find entry points
        if entry_classes:
            entries = [
                (cls, meth)
                for (cls, meth) in self._calls
                if cls in entry_classes
            ]
        else:
            # Methods with no callers
            all_called = set()
            for callees in self._calls.values():
                all_called.update(callees)
            entries = [m for m in self._calls if m not in all_called]

        paths: list[list[tuple[str, str]]] = []
        for entry in entries[:100]:  # cap to avoid explosion
            self._dfs(entry, targets, [entry], paths, max_depth)

        log.info("Found %d suspicious call paths", len(paths))
        return paths[:50]  # cap results

    def _dfs(
        self,
        current: tuple[str, str],
        targets: set[str],
        path: list[tuple[str, str]],
        results: list[list[tuple[str, str]]],
        max_depth: int,
    ) -> None:
        if len(path) > max_depth:
            return

        cls, meth = current
        if cls in targets or meth in targets:
            results.append(list(path))
            return

        for callee in self._calls.get(current, set()):
            if callee not in path:  # avoid cycles
                path.append(callee)
                self._dfs(callee, targets, path, results, max_depth)
                path.pop()

    def get_component_graph(
        self,
        components: dict[str, list[str]],
    ) -> list[CallEdge]:
        """Build edges between Android components based on class references.

        Parameters
        ----------
        components:
            Mapping of component type → list of class names.
        """
        all_components = set()
        for cls_list in components.values():
            all_components.update(cls_list)

        component_edges: list[CallEdge] = []
        for comp_cls in all_components:
            refs = self._class_refs.get(comp_cls, set())
            for ref in refs:
                if ref in all_components and ref != comp_cls:
                    component_edges.append(CallEdge(
                        caller_class=comp_cls,
                        caller_method="*",
                        callee_class=ref,
                        callee_method="*",
                        edge_type="component",
                    ))

        return component_edges

    def to_summary(self) -> dict:
        """Return a JSON-serializable summary of the graph."""
        return {
            "total_methods": self.method_count,
            "total_classes": self.class_count,
            "total_edges": self.edge_count,
            "top_callers": self._top_n(self._calls, 10),
            "top_callees": self._top_n(self._callers, 10),
        }

    @staticmethod
    def _top_n(
        index: dict[tuple[str, str], set[tuple[str, str]]], n: int
    ) -> list[dict]:
        ranked = sorted(index.items(), key=lambda x: len(x[1]), reverse=True)
        return [
            {"class": k[0], "method": k[1], "count": len(v)}
            for k, v in ranked[:n]
        ]
