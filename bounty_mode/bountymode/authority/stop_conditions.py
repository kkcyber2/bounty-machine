"""Stop-condition engine — global circuit breakers.

Where the authorization gate answers *may I test this target?*, the
stop-condition engine answers *should we still be running at all?*.

A stop-condition is a latch.  Once any condition fires the engine is in a
stopped state for the remainder of the session and the runner must abort.
Conditions are intentionally conservative and cheap to evaluate — they are
checked before every test case.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..errors import StopConditionError
from ..models import ProgramScope


@dataclass
class StopConditions:
    """Declarative budgets.  ``None`` disables an individual check."""

    max_requests: Optional[int] = 500
    max_duration_s: Optional[int] = 1800
    max_errors: Optional[int] = 10
    max_consecutive_errors: Optional[int] = 3
    kill_switch_file: Optional[str] = None

    @classmethod
    def from_scope(cls, scope: ProgramScope, **overrides: Optional[int]) -> "StopConditions":
        """Derive budgets from an imported program scope.

        The scope's numbers are *ceilings*: a caller may tighten them via
        ``overrides`` but the derived value is never raised here.
        """
        base = cls(
            max_requests=scope.max_requests,
            max_duration_s=scope.max_duration_s,
        )
        for key, value in overrides.items():
            if value is not None:
                setattr(base, key, value)
        return base


@dataclass
class StopState:
    """Live counters + latch state for one session."""

    requests_made: int = 0
    errors: int = 0
    consecutive_errors: int = 0
    cases_completed: int = 0
    started_at: float = field(default_factory=time.monotonic)
    stopped: bool = False
    fired: Optional[str] = None
    detail: str = ""
    fired_at: Optional[float] = None

    def elapsed_s(self) -> float:
        return time.monotonic() - self.started_at

    def to_dict(self) -> Dict[str, object]:
        return {
            "requests_made": self.requests_made,
            "errors": self.errors,
            "consecutive_errors": self.consecutive_errors,
            "cases_completed": self.cases_completed,
            "elapsed_s": round(self.elapsed_s(), 3),
            "stopped": self.stopped,
            "fired": self.fired,
            "detail": self.detail,
        }


class StopConditionEngine:
    """Evaluate budgets and latch on the first violation."""

    def __init__(self, conditions: StopConditions) -> None:
        self.conditions = conditions
        self.state = StopState()
        self.history: List[Dict[str, object]] = []

    # -- counters ---------------------------------------------------------- #

    def record_request(self, n: int = 1) -> None:
        self.state.requests_made += n

    def record_success(self) -> None:
        self.state.consecutive_errors = 0
        self.state.cases_completed += 1

    def record_error(self, exc: Optional[BaseException] = None) -> None:
        self.state.errors += 1
        self.state.consecutive_errors += 1
        if exc is not None:
            self.state.detail = str(exc)[:200]

    def request_kill(self, reason: str = "operator requested stop") -> None:
        """Manual kill switch (also used by the CLI on Ctrl-C).

        Latches the state **without** raising — the next :meth:`check` is what
        raises, so a caller can request a stop and then unwind cleanly.
        """
        self._latch("kill_switch", reason)

    # -- evaluation -------------------------------------------------------- #

    def check(self) -> StopState:
        """Raise :class:`StopConditionError` when a condition fires.

        Returns the current state when nothing has fired, so a caller can log
        progress without a second accessor.
        """
        c = self.conditions
        s = self.state

        if s.stopped:
            raise StopConditionError(s.fired or "stopped", s.detail)

        if c.kill_switch_file:
            import os

            if os.path.exists(c.kill_switch_file):
                self._fire("kill_switch_file", c.kill_switch_file)

        if c.max_requests is not None and s.requests_made >= c.max_requests:
            self._fire("max_requests", f"{s.requests_made}/{c.max_requests}")

        if c.max_duration_s is not None and s.elapsed_s() >= c.max_duration_s:
            self._fire("max_duration", f"{s.elapsed_s():.0f}s/{c.max_duration_s}s")

        if c.max_errors is not None and s.errors >= c.max_errors:
            self._fire("max_errors", f"{s.errors}/{c.max_errors}")

        if c.max_consecutive_errors is not None and s.consecutive_errors >= c.max_consecutive_errors:
            self._fire("max_consecutive_errors", f"{s.consecutive_errors}")

        return s

    def _latch(self, condition: str, detail: str) -> None:
        """Record a firing without raising (idempotent)."""
        if self.state.stopped:
            return
        self.state.stopped = True
        self.state.fired = condition
        self.state.detail = detail
        self.state.fired_at = time.monotonic()
        self.history.append(
            {"condition": condition, "detail": detail, "elapsed_s": round(self.state.elapsed_s(), 3)}
        )

    def _fire(self, condition: str, detail: str) -> None:
        if self.state.stopped:
            raise StopConditionError(self.state.fired or condition, self.state.detail)
        self._latch(condition, detail)
        raise StopConditionError(condition, detail)
