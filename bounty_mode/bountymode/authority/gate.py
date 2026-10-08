"""Authorization gate — the single choke-point every test must pass.

The gate combines three independent checks and returns a decision.  A test may
only run when **all three** pass:

1. **Scope** — the target resolves to an in-scope asset and matches no
   exclusion rule (see :mod:`bountymode.scope`).
2. **Technique policy** — the technique is not prohibited by the program, and
   if the technique is ``destructive`` it must be explicitly permitted.
3. **Human-in-the-loop** — techniques flagged ``side_effects`` require an
   audited approval that has been registered with the gate.

The gate never performs network I/O.  It is a pure decision function over
declarative data, which is what makes it testable and auditable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from ..models import (
    AuthorizationDecision,
    ProgramScope,
    Technique,
    Verdict,
)
from ..scope.matcher import resolve_scope, technique_prohibited


@dataclass
class Approval:
    """An audited human approval for one side-effecting technique/target."""

    target: str
    technique_id: str
    approved_by: str
    approved_at: str
    note: str = ""


class AuthorizationGate:
    """Decide whether a (target, technique) pair may be tested."""

    def __init__(self, scope: ProgramScope, *, require_human_for_side_effects: bool = True) -> None:
        self.scope = scope
        self.require_human_for_side_effects = require_human_for_side_effects
        self._approvals: Dict[str, Approval] = {}
        self.decisions: List[AuthorizationDecision] = []

    # -- approvals --------------------------------------------------------- #

    def register_approval(self, approval: Approval) -> None:
        self._approvals[self._key(approval.target, approval.technique_id)] = approval

    def has_approval(self, target: str, technique_id: str) -> bool:
        return self._key(target, technique_id) in self._approvals

    # -- decision ---------------------------------------------------------- #

    def authorize(self, target: str, technique: Technique) -> AuthorizationDecision:
        """Return a decision for one test.  Never raises for a *denial* —
        denials are data, and the caller records them."""
        decision = self._evaluate(target, technique)
        self.decisions.append(decision)
        return decision

    def require(self, target: str, technique: Technique) -> AuthorizationDecision:
        """Like :meth:`authorize` but raises for anything that is not ALLOW.

        The runner uses this so an out-of-scope call cannot silently continue.
        """
        decision = self.authorize(target, technique)
        if decision.verdict == Verdict.DENY:
            from ..errors import ScopeViolationError

            raise ScopeViolationError(target, decision.reason)
        if decision.verdict == Verdict.NEEDS_HUMAN:
            from ..errors import AuthorizationError

            raise AuthorizationError(target, decision.reason)
        return decision

    # -- internals --------------------------------------------------------- #

    def _evaluate(self, target: str, technique: Technique) -> AuthorizationDecision:
        tid = technique.id

        if technique.destructive:
            return AuthorizationDecision(
                target=target,
                technique_id=tid,
                verdict=Verdict.DENY,
                reason="destructive techniques are blocked in Bounty Mode",
                matched_exclusion="destructive",
            )

        in_scope, entry, exclusion = resolve_scope(target, self.scope)
        if exclusion is not None:
            return AuthorizationDecision(
                target=target,
                technique_id=tid,
                verdict=Verdict.DENY,
                reason=f"matches out-of-scope rule: {exclusion.pattern}",
                matched_exclusion=exclusion.pattern,
            )
        if not in_scope or entry is None:
            return AuthorizationDecision(
                target=target,
                technique_id=tid,
                verdict=Verdict.DENY,
                reason="target is not covered by any in-scope asset",
            )

        if technique_prohibited(tid, self.scope):
            return AuthorizationDecision(
                target=target,
                technique_id=tid,
                verdict=Verdict.DENY,
                reason=f"technique '{tid}' is prohibited by this program",
                matched_scope=entry.pattern,
                matched_exclusion=f"technique:{tid}",
            )

        if self.require_human_for_side_effects and technique.side_effects:
            if not self.has_approval(target, tid):
                return AuthorizationDecision(
                    target=target,
                    technique_id=tid,
                    verdict=Verdict.NEEDS_HUMAN,
                    reason="technique has side effects and no human approval is registered",
                    matched_scope=entry.pattern,
                )
            return AuthorizationDecision(
                target=target,
                technique_id=tid,
                verdict=Verdict.ALLOW,
                reason="in scope; prohibited-free; human approval registered",
                matched_scope=entry.pattern,
                human_approved=True,
            )

        return AuthorizationDecision(
            target=target,
            technique_id=tid,
            verdict=Verdict.ALLOW,
            reason="in scope; technique permitted",
            matched_scope=entry.pattern,
        )

    @staticmethod
    def _key(target: str, technique_id: str) -> str:
        return f"{target.strip().lower()}::{technique_id.strip().lower()}"

    # -- reporting --------------------------------------------------------- #

    def summary(self) -> Dict[str, int]:
        counts = {"allow": 0, "deny": 0, "needs_human": 0}
        for d in self.decisions:
            counts[d.verdict.value] += 1
        return counts
