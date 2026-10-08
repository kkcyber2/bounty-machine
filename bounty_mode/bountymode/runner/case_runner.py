"""Bounty Mode case runner.

Executes a *case* — one program, one target, a list of techniques — by
iterating techniques **one at a time** and routing each through the gate, the
stop-condition engine and the evidence vault.

Invariants the runner enforces by construction:

1. A technique whose gate decision is not ``ALLOW`` is never dispatched.  It is
   recorded in ``skipped`` with the reason.
2. Stop-conditions are checked *before* each dispatch, so a fired budget halts
   the run immediately and latches.
3. Every successful result is captured to the vault before it is turned into a
   finding, so evidence can never be lost.
4. A dispatcher that raises is recorded as an error, never a success.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..authority.gate import AuthorizationGate
from ..authority.stop_conditions import StopConditionEngine
from ..dedupe.registry import DedupRegistry, DedupVerdict
from ..errors import StopConditionError
from ..evidence.vault import EvidenceVault
from ..models import Finding, ProgramScope, Technique, json_dumps
from .adapter import EngineResult, FindingBuilder, TechniqueRegistry

Dispatcher = Callable[[Technique, str], EngineResult]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CaseResult:
    case_id: str
    program: str
    target: str
    started_at: str = field(default_factory=_now_iso)
    finished_at: str = ""
    findings: List[Finding] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    requests_made: int = 0
    stopped: bool = False
    stop_reason: str = ""
    gate_summary: Dict[str, int] = field(default_factory=dict)
    stop_state: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "program": self.program,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "findings": [f.to_dict() for f in self.findings],
            "skipped": self.skipped,
            "errors": self.errors,
            "requests_made": self.requests_made,
            "stopped": self.stopped,
            "stop_reason": self.stop_reason,
            "gate_summary": self.gate_summary,
            "stop_state": self.stop_state,
        }


class CaseRunner:
    """Run one case behind the safety gates."""

    def __init__(
        self,
        *,
        gate: AuthorizationGate,
        stops: StopConditionEngine,
        vault: EvidenceVault,
        dedup: Optional[DedupRegistry] = None,
        dispatch: Optional[Dispatcher] = None,
        registry: Optional[TechniqueRegistry] = None,
    ) -> None:
        self.gate = gate
        self.stops = stops
        self.vault = vault
        self.dedup = dedup
        self.dispatch = dispatch
        self.registry = registry or TechniqueRegistry()
        self.builder = FindingBuilder()

    # -- main loop --------------------------------------------------------- #

    def run(
        self,
        case_id: str,
        scope: ProgramScope,
        target: str,
        techniques: List[str],
    ) -> CaseResult:
        result = CaseResult(case_id=case_id, program=scope.program, target=target)

        for key in techniques:
            technique = self.registry.get(key)
            if technique is None:
                result.errors.append({"technique": key, "error": "unknown technique"})
                continue

            decision = self.gate.authorize(target, technique)
            if not decision.allowed:
                result.skipped.append(
                    {"technique": technique.id, "reason": decision.reason,
                     "verdict": decision.verdict.value}
                )
                continue

            # Stop-conditions are checked immediately before a real dispatch.
            try:
                self.stops.check()
            except StopConditionError as exc:
                result.stopped = True
                result.stop_reason = str(exc)
                result.skipped.append(
                    {"technique": technique.id, "reason": f"halted: {exc}", "verdict": "halted"}
                )
                break

            if self.dispatch is None:
                result.skipped.append(
                    {"technique": technique.id, "reason": "dry run (no dispatcher)",
                     "verdict": "allow"}
                )
                continue

            self.stops.record_request()
            result.requests_made += 1
            try:
                engine_result = self.dispatch(technique, target)
            except Exception as exc:  # noqa: BLE001 - contained on purpose
                self.stops.record_error(exc)
                result.errors.append({"technique": technique.id, "error": str(exc)})
                continue

            if engine_result.error:
                self.stops.record_error(RuntimeError(engine_result.error))
                result.errors.append(
                    {"technique": technique.id, "error": engine_result.error}
                )
                continue

            self.stops.record_success()

            if not engine_result.success:
                continue

            finding = self.builder.build(engine_result, technique)

            # Capture evidence *before* anything else touches the finding.
            self.vault.capture(
                finding,
                kind="prompt" if technique.category != "access_control" else "http",
                request=engine_result.payload_used,
                response=engine_result.response,
                url=target,
                method="POST",
            )

            if self.dedup is not None:
                verdict = self.dedup.register(finding)
                if verdict is DedupVerdict.DUPLICATE:
                    result.skipped.append(
                        {"technique": technique.id, "reason": "duplicate of a known finding",
                         "verdict": "duplicate"}
                    )
                    continue

            result.findings.append(finding)

        result.finished_at = _now_iso()
        result.gate_summary = self.gate.summary()
        result.stop_state = self.stops.state.to_dict()
        return result

    # -- output ------------------------------------------------------------ #

    @staticmethod
    def write_result(result: CaseResult, path: str) -> str:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        return str(p)
