"""Drake-X safety layer.

The safety layer enforces three orthogonal guardrails for any action the
engine wants to take:

1. **Engagement scope** — :class:`ScopeEnforcer` rejects targets that are
   not declared in-scope by the operator's :class:`ScopeFile`.
2. **Active-action policy** — :class:`PolicyClassifier` labels modules and
   integrations as passive or active and refuses to escalate without an
   explicit operator override.
3. **Confirmation** — :class:`ConfirmGate` prompts the operator before
   active actions, unless ``--yes``/``--dry-run`` overrides apply.

The safety layer never invokes tools itself; it only says yes/no.
"""

from .confirm import ConfirmGate
from .enforcer import ScopeEnforcer
from .policy import ActionPolicy, PolicyClassifier, PolicyDecision
from .scope_file import (
    DEFAULT_SCOPE_TEMPLATE,
    load_scope_file,
    save_scope_file,
    write_scope_template,
)

__all__ = [
    "ConfirmGate",
    "ScopeEnforcer",
    "ActionPolicy",
    "PolicyClassifier",
    "PolicyDecision",
    "DEFAULT_SCOPE_TEMPLATE",
    "load_scope_file",
    "save_scope_file",
    "write_scope_template",
]
