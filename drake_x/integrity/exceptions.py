"""Integrity-specific exceptions.

All exceptions inherit from :class:`drake_x.exceptions.DrakeXError`.
The fail-closed design means integrity violations raise rather than
allow processing to continue with unverified data.
"""

from __future__ import annotations

from ..exceptions import DrakeXError


class IntegrityError(DrakeXError):
    """Base class for all integrity errors."""


class HashMismatchError(IntegrityError):
    """A computed hash does not match the expected value.

    This is a fail-closed error: processing must stop when artifact
    integrity cannot be verified.
    """

    def __init__(self, artifact: str, expected: str, actual: str) -> None:
        self.artifact = artifact
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Hash mismatch for {artifact}: expected {expected[:16]}…, "
            f"got {actual[:16]}…"
        )


class MissingArtifactError(IntegrityError):
    """A required artifact is missing from the integrity chain."""


class CustodyChainError(IntegrityError):
    """The chain of custody is broken or inconsistent."""


class MissingRunIdError(IntegrityError):
    """A required run_id is missing from an event or report."""


class IntegrityVerificationError(IntegrityError):
    """The integrity verification check found one or more violations."""

    def __init__(self, violations: list[str]) -> None:
        self.violations = violations
        summary = "; ".join(violations[:5])
        if len(violations) > 5:
            summary += f" (and {len(violations) - 5} more)"
        super().__init__(f"Integrity verification failed: {summary}")
