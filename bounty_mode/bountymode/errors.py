"""Exception hierarchy for Bounty Mode.

All errors inherit from :class:`BountyModeError` so a caller can catch the
whole family with one ``except``.  The safety-critical errors
(:class:`ScopeViolationError`, :class:`AuthorizationError`,
:class:`StopConditionError`) are deliberately distinct from generic runtime
problems so that a runner can treat "the gate said no" differently from
"the network died".
"""

from __future__ import annotations


class BountyModeError(Exception):
    """Base class for every Bounty Mode error."""


class ScopeViolationError(BountyModeError):
    """Raised when a target is not covered by the imported program scope.

    This is a *hard* failure: the engine must never be allowed to touch a
    target that raises this.
    """

    def __init__(self, target: str, reason: str = "not in scope") -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"out of scope: {target!r} ({reason})")


class AuthorizationError(BountyModeError):
    """Raised when the authorization gate refuses to grant a decision."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"not authorized: {target!r} ({reason})")


class StopConditionError(BountyModeError):
    """Raised when a stop-condition fires and testing must halt.

    Stop-conditions are global circuit breakers (kill switch, request budget,
    error budget, time budget).  Once one fires the runner latches into a
    stopped state and no further test cases execute.
    """

    def __init__(self, condition: str, detail: str = "") -> None:
        self.condition = condition
        self.detail = detail
        msg = f"stop condition fired: {condition}"
        if detail:
            msg += f" ({detail})"
        super().__init__(msg)


class EvidenceError(BountyModeError):
    """Raised when evidence cannot be captured or persisted safely."""


class ReportError(BountyModeError):
    """Raised when a report cannot be rendered or a required field is missing."""
