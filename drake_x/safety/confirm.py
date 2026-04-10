"""Operator confirmation gate.

Active and intrusive actions cannot run unless the operator explicitly
agrees. The gate supports three modes:

- ``interactive`` (default) — prompts on stdin
- ``yes``                  — pre-approved (`--yes`); still logs and warns
- ``deny``                 — refuses everything that isn't passive

The gate is intentionally non-async because confirmation is rare,
synchronous, and must block the engine until the operator answers.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import StrEnum

from ..exceptions import ConfirmationDeniedError


class ConfirmMode(StrEnum):
    INTERACTIVE = "interactive"
    YES = "yes"
    DENY = "deny"


@dataclass
class ConfirmGate:
    """Tiny synchronous confirmation gate."""

    mode: ConfirmMode = ConfirmMode.INTERACTIVE

    def require(self, *, action: str, target: str, policy: str) -> None:
        """Block until the operator approves ``action`` against ``target``.

        Raises :class:`ConfirmationDeniedError` if the operator declines or
        the gate is in deny mode.
        """
        if self.mode == ConfirmMode.YES:
            return
        if self.mode == ConfirmMode.DENY:
            raise ConfirmationDeniedError(
                f"confirmation gate is in deny mode; refusing {action} ({policy}) on {target}"
            )

        if not sys.stdin or not sys.stdin.isatty():
            raise ConfirmationDeniedError(
                f"interactive confirmation required for {action} ({policy}) on {target}, "
                "but stdin is not a TTY. Re-run with --yes after reviewing the plan."
            )

        prompt = (
            f"\n[!] Active action requested:\n"
            f"    integration: {action}\n"
            f"    policy:      {policy}\n"
            f"    target:      {target}\n"
            f"  Proceed? (yes/no) > "
        )
        sys.stdout.write(prompt)
        sys.stdout.flush()
        try:
            answer = input().strip().lower()
        except EOFError as exc:
            raise ConfirmationDeniedError(
                "no input received at confirmation gate"
            ) from exc

        if answer not in {"y", "yes"}:
            raise ConfirmationDeniedError(
                f"operator declined {action} ({policy}) on {target}"
            )
