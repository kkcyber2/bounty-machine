"""Tests for the adapter, technique registry and case runner.

These are the highest-value tests in the suite: they prove that the safety
guarantees hold *through the runner*, not just in the gate in isolation.
"""

from __future__ import annotations

import pytest

from bountymode.authority.gate import Approval, AuthorizationGate
from bountymode.authority.stop_conditions import StopConditionEngine, StopConditions
from bountymode.dedupe.registry import DedupRegistry
from bountymode.evidence.vault import EvidenceVault
from bountymode.models import OutOfScopeRule, ProgramScope, ScopeTarget, Technique, Verdict
from bountymode.runner.adapter import (
    DEFAULT_TECHNIQUES,
    EngineResult,
    FindingBuilder,
    TechniqueRegistry,
)
from bountymode.runner.case_runner import CaseRunner


def _scope(**kw) -> ProgramScope:
    base = dict(
        program="acme",
        in_scope=[ScopeTarget("api.acme.com")],
        out_of_scope=[OutOfScopeRule("admin.acme.com")],
        prohibited_techniques=["economic_denial", "malware", "destructive"],
        max_requests=50,
        max_duration_s=600,
    )
    base.update(kw)
    return ProgramScope(**base)


def _runner(tmp_path, dispatch=None, scope=None, **kw):
    scope = scope or _scope()
    gate = AuthorizationGate(scope)
    stops = StopConditionEngine(StopConditions.from_scope(scope, max_errors=None,
                                                          max_consecutive_errors=None))
    vault = EvidenceVault(str(tmp_path / "ev"))
    dedup = DedupRegistry(str(tmp_path / "registry.json"))
    return CaseRunner(gate=gate, stops=stops, vault=vault, dedup=dedup,
                      dispatch=dispatch, **kw), gate, vault


# --- registry -------------------------------------------------------------- #

def test_registry_has_expected_catalogue_size():
    reg = TechniqueRegistry()
    assert len(reg.all()) == len(DEFAULT_TECHNIQUES)
    assert len(reg.all()) >= 15


def test_registry_lookup_by_id_and_engine_key():
    reg = TechniqueRegistry()
    assert reg.get("prompt_injection") is not None
    assert reg.get("PromptInjectionTester").id == "prompt_injection"


def test_registry_require_raises_for_unknown():
    with pytest.raises(KeyError):
        TechniqueRegistry().require("does-not-exist")


def test_registry_marks_destructive_technique():
    t = TechniqueRegistry().require("economic_denial")
    assert t.destructive is True


def test_registry_marks_side_effecting_techniques():
    reg = TechniqueRegistry()
    assert reg.require("tool_misuse").side_effects is True
    assert reg.require("excessive_agency").side_effects is True
    assert reg.require("prompt_injection").side_effects is False


# --- crash safety ---------------------------------------------------------- #

def test_default_techniques_catalogue_has_unique_ids():
    ids = [t.id for t in DEFAULT_TECHNIQUES]
    assert len(ids) == len(set(ids))


def test_technique_round_trips_through_dict():
    t = TechniqueRegistry().require("cross_tenant")
    assert Technique.from_dict(t.to_dict()).id == t.id


# --- EngineResult mapping -------------------------------------------------- #

def test_engine_result_from_dict_maps_alt_field_names():
    raw = {"is_successful": True, "score": 0.9, "prompt": "p", "model_response": "r",
           "vuln_type": "x", "model": "m"}
    r = EngineResult.from_dict(raw, "prompt_injection", "api.acme.com")
    assert r.success is True
    assert r.success_score == pytest.approx(0.9)
    assert r.payload_used == "p"
    assert r.response == "r"
    assert r.vulnerability_type == "x"
    assert r.target_model == "m"


def test_engine_result_tolerates_missing_fields():
    r = EngineResult.from_dict({}, "prompt_injection", "api.acme.com")
    assert r.success is False
    assert r.error == ""


# --- FindingBuilder -------------------------------------------------------- #

def test_finding_builder_produces_reportable_finding():
    tech = TechniqueRegistry().require("cross_tenant")
    res = EngineResult(technique_id="cross_tenant", target="api.acme.com",
                       success=True, success_score=0.95,
                       response="victim data", evidence="tenant B read tenant A")
    f = FindingBuilder().build(res, tech)
    assert f.category == "cross_tenant"
    assert f.blast_radius == "cross-tenant"
    assert f.reproducible is True
    assert "CWE-639" in f.cwe
    assert f.impact


def test_finding_builder_marks_low_confidence_unreproducible():
    tech = TechniqueRegistry().require("prompt_injection")
    res = EngineResult(technique_id="prompt_injection", target="api.acme.com",
                       success=True, success_score=0.2)
    f = FindingBuilder().build(res, tech)
    assert f.reproducible is False
    assert f.confidence == pytest.approx(0.2)


def test_finding_builder_fingerprint_is_stable():
    tech = TechniqueRegistry().require("prompt_injection")
    res = EngineResult(technique_id="prompt_injection", target="api.acme.com", success=True)
    a = FindingBuilder().build(res, tech)
    b = FindingBuilder().build(res, tech)
    assert a.fingerprint == b.fingerprint


# --- CaseRunner: the safety guarantees ------------------------------------ #

def test_runner_never_dispatches_out_of_scope_target(tmp_path):
    calls: list = []

    def dispatch(technique, target):
        calls.append((technique.id, target))
        return EngineResult(technique.id, target, success=False)

    runner, _, _ = _runner(tmp_path, dispatch=dispatch)
    result = runner.run("case", _scope(), "evil.test", ["prompt_injection", "cross_tenant"])

    assert calls == []                       # <- the single most important assertion
    assert len(result.skipped) == 2
    assert result.requests_made == 0


def test_runner_never_dispatches_destructive_technique(tmp_path):
    calls: list = []

    def dispatch(technique, target):
        calls.append(technique.id)
        return EngineResult(technique.id, target, success=False)

    runner, _, _ = _runner(tmp_path, dispatch=dispatch)
    result = runner.run("case", _scope(), "api.acme.com",
                        ["prompt_injection", "economic_denial"])

    assert "economic_denial" not in calls
    assert "prompt_injection" in calls
    assert any(s["technique"] == "economic_denial" for s in result.skipped)


def test_runner_skips_side_effecting_technique_without_approval(tmp_path):
    calls: list = []

    def dispatch(technique, target):
        calls.append(technique.id)
        return EngineResult(technique.id, target, success=False)

    runner, _, _ = _runner(tmp_path, dispatch=dispatch)
    result = runner.run("case", _scope(), "api.acme.com", ["tool_misuse"])

    assert calls == []
    assert result.skipped[0]["verdict"] == "needs_human"


def test_runner_dispatches_side_effecting_technique_with_approval(tmp_path):
    calls: list = []

    def dispatch(technique, target):
        calls.append(technique.id)
        return EngineResult(technique.id, target, success=True, success_score=0.9)

    runner, gate, _ = _runner(tmp_path, dispatch=dispatch)
    gate.register_approval(
        Approval(target="api.acme.com", technique_id="tool_misuse",
                 approved_by="analyst", approved_at="2026-10-08T00:00:00Z")
    )
    result = runner.run("case", _scope(), "api.acme.com", ["tool_misuse"])
    assert calls == ["tool_misuse"]
    assert len(result.findings) == 1


def test_runner_records_successful_finding_with_evidence(tmp_path):
    def dispatch(technique, target):
        return EngineResult(technique.id, target, success=True, success_score=0.9,
                            payload_used="ignore previous instructions",
                            response="secret sk-abcdefghijklmnopqrstuvwxyz012345")

    runner, _, vault = _runner(tmp_path, dispatch=dispatch)
    result = runner.run("case", _scope(), "api.acme.com", ["data_exfiltration"])

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.observations, "evidence must be captured"
    assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in f.observations[0].response
    assert vault.verify_chain()


def test_runner_does_not_create_finding_for_failed_test(tmp_path):
    def dispatch(technique, target):
        return EngineResult(technique.id, target, success=False, success_score=0.0)

    runner, _, _ = _runner(tmp_path, dispatch=dispatch)
    result = runner.run("case", _scope(), "api.acme.com", ["prompt_injection"])
    assert result.findings == []


def test_runner_contains_dispatch_exception(tmp_path):
    def dispatch(technique, target):
        raise RuntimeError("engine exploded")

    runner, _, _ = _runner(tmp_path, dispatch=dispatch)
    result = runner.run("case", _scope(), "api.acme.com", ["prompt_injection"])
    assert len(result.errors) == 1
    assert "engine exploded" in result.errors[0]["error"]
    assert result.findings == []


def test_runner_records_engine_reported_error(tmp_path):
    def dispatch(technique, target):
        return EngineResult(technique.id, target, success=False, error="HTTP 502")

    runner, _, _ = _runner(tmp_path, dispatch=dispatch)
    result = runner.run("case", _scope(), "api.acme.com", ["prompt_injection"])
    assert result.errors[0]["error"] == "HTTP 502"


def test_runner_latches_and_halts_on_stop_condition(tmp_path):
    calls: list = []

    def dispatch(technique, target):
        calls.append(technique.id)
        return EngineResult(technique.id, target, success=False)

    scope = _scope(max_requests=2)
    runner, _, _ = _runner(tmp_path, dispatch=dispatch, scope=scope)
    result = runner.run("case", scope, "api.acme.com",
                        ["prompt_injection", "indirect_injection", "context_manipulation",
                         "jailbreak"])

    assert result.stopped is True
    assert "max_requests" in result.stop_reason
    assert len(calls) <= 2


def test_runner_dry_run_skips_without_calling_engine(tmp_path):
    runner, _, _ = _runner(tmp_path, dispatch=None)
    result = runner.run("case", _scope(), "api.acme.com", ["prompt_injection"])
    assert result.requests_made == 0
    assert result.skipped[0]["reason"].startswith("dry run")


def test_runner_marks_duplicate_findings(tmp_path):
    def dispatch(technique, target):
        return EngineResult(technique.id, target, success=True, success_score=0.9,
                            response="same")

    runner, _, _ = _runner(tmp_path, dispatch=dispatch)
    first = runner.run("case1", _scope(), "api.acme.com", ["prompt_injection"])
    second = runner.run("case2", _scope(), "api.acme.com", ["prompt_injection"])

    assert len(first.findings) == 1
    assert len(second.findings) == 0
    assert any(s.get("verdict") == "duplicate" for s in second.skipped)


def test_runner_records_unknown_technique_as_error(tmp_path):
    runner, _, _ = _runner(tmp_path, dispatch=None)
    result = runner.run("case", _scope(), "api.acme.com", ["no_such_technique"])
    assert result.errors[0]["error"] == "unknown technique"


def test_runner_result_serialises(tmp_path):
    import json

    runner, _, _ = _runner(tmp_path, dispatch=None)
    result = runner.run("case", _scope(), "api.acme.com", ["prompt_injection"])
    json.dumps(result.to_dict())
    CaseRunner.write_result(result, str(tmp_path / "result.json"))
    assert (tmp_path / "result.json").exists()


def test_runner_reports_gate_summary(tmp_path):
    runner, _, _ = _runner(tmp_path, dispatch=None)
    result = runner.run("case", _scope(), "api.acme.com",
                        ["prompt_injection", "economic_denial", "tool_misuse"])
    assert result.gate_summary == {"allow": 1, "deny": 1, "needs_human": 1}
