"""Tests for the scope importer and matcher."""

from __future__ import annotations

import json

import pytest

from bountymode.models import OutOfScopeRule, ProgramScope, ScopeTarget
from bountymode.scope.importer import ScopeImporter
from bountymode.scope.matcher import (
    host_matches,
    resolve_scope,
    target_matches_pattern,
    technique_prohibited,
    url_matches,
)


POLICY = """
# Acme AI Assistant Bounty Program (HackerOne)

## In Scope
- https://api.acme.com
- chat.acme.com

## Out of Scope
- admin.acme.com
- Denial of service is prohibited

Rules: do not exceed 2 requests per second. Maximum 250 requests.
Safe harbour applies. Test accounts are available on request.
We operate a 90-day disclosure embargo.
"""


def _scope(**kw) -> ProgramScope:
    base = dict(
        program="acme",
        in_scope=[ScopeTarget("api.acme.com"), ScopeTarget("*.acme.ai")],
        out_of_scope=[OutOfScopeRule("admin.acme.com")],
    )
    base.update(kw)
    return ProgramScope(**base)


# --- host matching -------------------------------------------------------- #

def test_exact_host_matches_self_and_www():
    assert host_matches("example.com", "example.com")
    assert host_matches("example.com", "www.example.com")


def test_exact_host_does_not_match_subdomain():
    assert not host_matches("example.com", "api.example.com")


def test_wildcard_matches_subdomains_but_not_apex():
    assert host_matches("*.example.com", "api.example.com")
    assert host_matches("*.example.com", "deep.api.example.com")
    assert not host_matches("*.example.com", "example.com")


def test_host_matching_ignores_port_and_case():
    assert host_matches("API.Example.com:443", "api.example.com")


def test_url_prefix_matching():
    assert url_matches("https://api.example.com/v1", "https://api.example.com/v1/chat")
    assert not url_matches("https://api.example.com/v1", "https://api.example.com/v2/chat")


# --- target_matches_pattern ------------------------------------------------ #

def test_target_matches_url_prefix():
    assert target_matches_pattern("api.acme.com/v1/chat", "https://api.acme.com/v1")
    assert not target_matches_pattern("api.acme.com", "https://api.acme.com/v1")


def test_target_matches_glob_entry():
    assert target_matches_pattern("x.acme.ai", "*.acme.ai")
    assert not target_matches_pattern("acme.ai", "*.acme.ai")


def test_empty_inputs_never_match():
    assert not target_matches_pattern("", "*")
    assert not target_matches_pattern("example.com", "")


# --- resolve_scope -------------------------------------------------------- #

def test_resolve_scope_allows_listed_target():
    ok, entry, excl = resolve_scope("api.acme.com", _scope())
    assert ok and entry is not None and excl is None


def test_resolve_scope_exclusion_wins_over_inclusion():
    scope = _scope(
        in_scope=[ScopeTarget("acme.com"), ScopeTarget("admin.acme.com")],
        out_of_scope=[OutOfScopeRule("admin.acme.com")],
    )
    ok, entry, excl = resolve_scope("admin.acme.com", scope)
    assert not ok
    assert excl is not None and excl.pattern == "admin.acme.com"


def test_resolve_scope_unknown_target_is_out():
    ok, entry, excl = resolve_scope("evil.test", _scope())
    assert not ok and entry is None and excl is None


# --- technique policy ------------------------------------------------------ #

def test_technique_prohibited_respects_permit_override():
    scope = _scope(prohibited_techniques=["economic_denial", "malware"])
    assert technique_prohibited("malware", scope)
    assert not technique_prohibited("prompt_injection", scope)

    scope2 = _scope(
        prohibited_techniques=["economic_denial"],
        permitted_techniques=["economic_denial"],
    )
    assert not technique_prohibited("economic_denial", scope2)


# --- importer: JSON -------------------------------------------------------- #

def test_importer_from_dict_accepts_string_entries():
    scope = ScopeImporter().from_dict(
        {"program": "acme", "in_scope": ["a.com", "b.com"], "out_of_scope": ["x.com"]}
    )
    assert {t.pattern for t in scope.in_scope} == {"a.com", "b.com"}
    assert scope.out_of_scope[0].pattern == "x.com"


def test_importer_normalises_camel_case_keys():
    scope = ScopeImporter().from_dict(
        {"title": "acme", "inScope": ["a.com"], "outOfScope": ["b.com"]}
    )
    assert scope.program == "acme"
    assert scope.in_scope[0].pattern == "a.com"
    assert scope.out_of_scope[0].pattern == "b.com"


def test_importer_merges_always_prohibited_classes():
    scope = ScopeImporter().from_dict={"{"program": "acme"}
    assert "economic_denial" in scope.prohibited_techniques
    assert "destructive" in scope.prohibited_techniques
    assert "malware" in scope.prohibited_techniques


# --- importer: text -------------------------------------------------------- #

def test_importer_text_extracts_scope_and_limits():
    scope = ScopeImporter().from_text(POLICY, program="acme")
    patterns = {t.pattern for t in scope.in_scope}
    assert "api.acme.com" in patterns
    assert "chat.acme.com" in patterns
    assert {r.pattern for r in scope.out_of_scope} >= {"admin.acme.com"}
    assert scope.rate_limit_rps == pytest.approx(2.0)
    assert scope.max_requests == 250
    assert scope.safe_harbour is True
    assert scope.disclosure_days == 90
    assert scope.prohibited_techniques  # DoS merged/derived
    assert scope.platform == "hackerone"


def test_importer_text_refuses_unsafe_hosts():
    scope = ScopeImporter().from_text(
        "## In Scope\n- localhost\n- 169.254.169.254\n- real.example.com\n"
    )
    patterns = {t.pattern for t in scope.in_scope}
    assert "localhost" not in patterns
    assert "169.254.169.254" not in patterns
    assert "real.example.com" in patterns


def test_importer_text_warns_when_nothing_found():
    imp = ScopeImporter()
    imp.from_text("This policy mentions no assets at all.")
    assert imp.warnings


# --- round-trip ------------------------------------------------------------ #

def test_scope_json_round_trip(tmp_path):
    imp = ScopeImporter()
    original = imp.from_text(POLICY, program="acme")
    out = tmp_path / "scope.json"
    imp.export(original, str(out))

    reloaded = ScopeImporter().import_file(str(out))
    assert reloaded.program == original.program
    assert {t.pattern for t in reloaded.in_scope} == {t.pattern for t in original.in_scope}
    assert reloaded.max_requests == original.max_requests
    assert reloaded.prohibited_techniques == original.prohibited_techniques


def test_scope_from_dict_ignores_unknown_keys():
    scope = ProgramScope.from_dict(
        {"program": "acme", "in_scope": ["a.com"], "totally_unknown_field": 1}
    )
    assert scope.program == "acme"
