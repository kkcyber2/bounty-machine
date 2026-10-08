"""Tests for the authorization gate and stop-condition engine."""

from __future__ import annotations

import pytest

from bountymode.authority.gate import Approval, AuthorizationGate
from bountymode.authority.stop_conditions import StopConditionEngine, StopConditions
from bountymode.errors import AuthorizationError, ScopeViolationError, StopConditionError
from bountymode.models import (
    OutOfScopeRule,
    ProgramScope,
    ScopeTarget,
    Technique,
    Verdict,
)


def _scope(**kw) -> ProgramScope:
    base = dict(
        program="acme",
        in_scope=[ScopeTarget("api.acme.com")],
        out_of_scope=[OutOfScopeRule("admin.acme.com")],
        prohibited_techniques=["economic_denial", "malware"],
        max_requests=100,
        max_duration_s=600,
    )
    base.update(kw)
    return ProgramScope(**base)


def _tech(id="prompt_injection", **kw) -> Technique:
    return Technique(id=id, name=id, engine_key=id, **kw)


# --- gate: scope ----------------------------------------------------------- #

def test_gate_allows_in_scope_permitted_technique():
    gate = AuthorizationGate(_scope())
    d = gate.authorize("api.acme.com", _tech())
    assert d.verdict is Verdict.ALLOW
    assert d.matched_scope == "api.acme.com"
    assert d.allowed


def test_gate_denies_out_of_scope_target():
    gate = AuthorizationGate(_scope())
    d = gate.authorize("evil.test", _tech())
    assert d.verdict is Verdict.DENY
    assert "not covered" in d.reason


def test_gate_denies_excluded_target_even_when_listed():
    scope = _scope(
        in_scope=[ScopeTarget("acme.com"), ScopeTarget("admin.acme.com")],
        out_of_scope=[OutOfScopeRule("admin.acme.com")],
    )
    gate = AuthorizationGate(scope)
    d = gate.authorize("admin.acme.com", _tech())
    assert d.verdict is Verdict.DENY
    assert d.matched_exclusion == "admin.acme.com"


# --- gate: technique policy ------------------------------------------------ #

def test_gate_blocks_prohibited_technique():
    gate = AuthorizationGate(_scope())
    d = gate.authorize("api.acme.com", _tech("malware"))
    assert d.verdict is Verdict.DENY
    assert "prohibited" in d.reason


def test_gate_blocks_destructive_technique_even_when_in_scope():
    gate = AuthorizationGate(_scope(prohibited_techniques=[]))
    d = gate.authorize("api.acme.com", _tech("economic_denial", destructive=True))
    assert d.verdict is Verdict.DENY
    assert "destructive" in d.reason


# --- gate: human-in-the-loop ---------------------------------------------- #

def test_gate_requires_human_for_side_effects():
    gate = AuthorizationGate(_scope())
    d = gate.authorize("api.acme.com", _tech("tool_misuse", side_effects=True))
    assert d.verdict is Verdict.NEEDS_HUMAN
    assert "side effects" in d.reason


def test_gate_requires_human_for_side_effects_then_allows_after_approval():
    gate = AuthorizationGate(_scope())
    tech = _tech("tool_misuse", side_effects=True)

    assert gate.authorize("api.acme.com", tech).verdict is Verdict.NEEDS_HUMAN

    gate.register_approval(
        Approval(
            target="api.acme.com",
            technique_id="tool_misuse",
            approved_by="analyst",
            approved_at="2026-10-08T00:00:00Z",
        )
    )
    d = gate.authorize("api.acme.com", tech)
    assert d.verdict is Verdict.ALLOW
    assert d.human_approved is True


def test_approval_is_scoped_to_target_and_technique():
    gate = AuthorizationGate(_scope())
    gate.register_approval(
        Approval(target="api.acme.com", technique_id="tool_misuse",
                 approved_by="a", approved_at="t")
    )
    # different technique -> still needs human
    assert gate.authorize(
        "api.acme.com", _tech("excessive_agency", side_effects=True)
    ).verdict is Verdict.NEEDS_HUMAN


# --- gate: require() ------------------------------------------------------- #

def test_gate_require_raises_for_out_of_scope():
    gate = AuthorizationGate(_scope())
    with pytest.raises(ScopeViolationError):
        gate.require("evil.test", _tech())


def test_gate_require_raises_for_needs_human():
    gate = AuthorizationGate(_scope())
    with pytest.raises(AuthorizationError):
        gate.require("api.acme.com", _tech("tool_misuse", side_effects=True))


def test_gate_require_returns_decision_when_allowed():
    gate = AuthorizationGate(_scope())
    d = gate.require("api.acme.com", _tech())
    assert d.allowed


# --- gate: bookkeeping ----------------------------------------------------- #

def test_gate_summary_counts_verdicts():
    gate = AuthorizationGate(_scope())
    gate.authorize("api.acme.com", _tech())
    gate.authorize("evil.test", _tech())
    gate.authorize("api.acme.com", _tech("tool_misuse", side_effects=True))
    s = gate.summary()
    assert s == {"allow": 1, "deny": 1, "needs_human": 1}


def test_decision_is_json_serialisable():
    gate = AuthorizationGate(_scope())
    d = gate.authorize("api.acme.com", _tech())
    assert d.to_dict()["verdict"] == "allow"


# --- stop conditions ------------------------------------------------------- #

def test_stop_conditions_from_scope_uses_scope_budgets():
    c = StopConditions.from_scope(_scope())
    assert c.max_requests == 100
    assert c.max_duration_s == 600


def test_stop_conditions_from_scope_allows_tightening_only():
    c = StopConditions.from_scope(_scope(), max_requests=5)
    assert c.max_requests == 5


def test_stop_fires_on_request_budget():
    eng = StopConditionEngine(StopConditions(max_requests=2, max_duration_s=None,
                                             max_errors=None, max_consecutive_errors=None))
    eng.record_request()
    eng.check()
    eng.record_request()
    with pytest.raises(StopConditionError) as ei:
        eng.check()
    assert "max_requests" in str(ei.value)


def test_stop_fires_on_consecutive_errors():
    eng = StopConditionEngine(StopConditions(max_requests=None, max_duration_s=None,
                                             max_errors=None, max_consecutive_errors=2))
    eng.record_error(RuntimeError("boom"))
    eng.check()
    eng.record_error(RuntimeError("boom"))
    with pytest.raises(StopConditionError):
        eng.check()


def test_consecutive_error_counter_resets_on_success():
    eng = StopConditionEngine(StopConditions(max_requests=None, max_duration_s=None,
                                             max_errors=None, max_consecutive_errors=2))
    eng.record_error(RuntimeError("x"))
    eng.record_success()
    eng.record_error(RuntimeError("y"))
    eng.check()  # should not raise
    assert eng.state.consecutive_errors == 1


def test_stop_latches_after_firing():
    eng = StopConditionEngine(StopConditions(max_requests=1, max_duration_s=None,
                                             max_errors=None, max_consecutive_errors=None))
    eng.record_request()
    with pytest.raises(StopConditionError):
        eng.check()
    assert eng.state.stopped is True
    # a second check still raises even with no new requests
    eng.state.requests_made = 0
    with pytest.raises(StopConditionError):
        eng.check()


def test_kill_switch_latches_without_raising_immediately():
    eng = StopConditionEngine(StopConditions(max_requests=None, max_duration_s=None))
    eng.request_kill("operator pressed stop")
    assert eng.state.stopped is True
    with pytest.raises(StopConditionError):
        eng.check()


def test_kill_switch_file_is_honoured(tmp_path):
    flag = tmp_path / "STOP"
    eng = StopConditionEngine(
        StopConditions(max_requests=None, max_duration_s=None, kill_switch_file=str(flag))
    )
    eng.check()  # no file -> fine
    flag.write_text("stop")
    with pytest.raises(StopConditionError) as ei:
        eng.check()
    assert "kill_switch_file" in str(ei.value)


def test_stop_state_is_serialisable():
    eng = StopConditionEngine(StopConditions())
    d = eng.state.to_dict()
    assert set(["requests_made", "stopped", "fired"]).issubset(d)
