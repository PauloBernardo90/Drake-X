"""Cross-sample / cross-session correlation (v1.0).

This package lifts the Evidence Graph from a per-session artifact into a
workspace-level queryable surface. Every graph persisted via
:class:`drake_x.core.storage.WorkspaceStorage` is fair game; correlation
is computed deterministically from node evidence, never invented.

Public API:

- :func:`load_all_graphs` — load every persisted graph in the workspace
- :func:`correlate_samples` — surface deterministic cross-sample links
- :func:`query_nodes` — workspace-wide filtered node query

See ``drake_x/models/correlation.py`` for the output schema.
"""

from .correlator import (
    correlate_samples,
    load_all_graphs,
    query_nodes,
)

__all__ = ["correlate_samples", "load_all_graphs", "query_nodes"]
