"""Tests for CVSS, triage scoring, report generation and de-duplication."""

from __future__ import annotations

import pytest

from bountymode.dedupe.registry import DedupRegistry, DedupVerdict
from bountymode.models import Finding, Observation, Severity
from bountymode.report.generator import ReportGenerator
from bountymode.triage.cvss import CVSSv31, parse_vector, score_vector
from bountymode.triage.scorer import TriageScorer


# --- CVSS ------------------------------------------------------------------ #

@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_reference_vectors(vector, expected):
    assert score_vector(vector) == pytest.approx(expected, abs=0.05)


def test_cvss_round_trip_vector_string():
    v = CVSSv31(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
    assert v.vector() == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert CVSSv31.from_vector(v.vector()).base_score() == pytest.approx(9.8)


def test_parse_vector_rejects_garbage():
    assert parse_vector("not-a-vector") is None
    assert parse_vector("") is None


def test_parse_vector_accepts_valid():
    assert parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is not None


# --- triage ---------------------------------------------------------------- #

def _f(**kw) -> Finding:
    base = dict(
        id="F-1",
        title="Cross-tenant disclosure",
        technique_id="cross_tenant",
        target="api.acme.com",
        category="cross_tenant",
        reproducible=True,
        reproduction_rate=1.0,
        confidence=0.95,
        blast_radius="cross-tenant",
        privileges_required="low",
    )
    base.update(kw)
    return Finding(**base)


def test_scorer_ranks_cross_tenant_above_jailbreak():
    scorer = TriageScorer()
    cross = scorer.score(_f())
    jail = scorer.score(_f(id="F-2", category="jailbreak", title="jailbreak",
                          technique_id="jailbreak", blast_radius="single-user"))
    assert cross.cvss_score > jail.cvss_score
    assert cross.priority > jail.priority


def test_scorer_downgrades_unreproducible():
    scorer = TriageScorer()
    good = scorer.score(_f())
    bad = scorer.score(_f(id="F-3", reproducible=False, reproduction_rate=0.0))
    assert bad.cvss_score < good.cvss_score
    assert bad.priority == 0


def test_scorer_downgrades_low_confidence():
    scorer = TriageScorer()
    hi = scorer.score(_f(id="F-4"))
    lo = scorer.score(_f(id="F-5", confidence=0.3))
    assert lo.cvss_score < hi.cvss_score


def test_scorer_caps_plain_jailbreak():
    scorer = TriageScorer()
    r = scorer.score(_f(id="F-6", category="jailbreak", technique_id="jailbreak",
                        title="bypass", blast_radius="single-user"))
    assert r.cvss_score <= 3.9
    assert r.priority == 0  # below submit threshold


def test_scorer_assigns_severity_from_score():
    scorer = TriageScorer()
    r = scorer.score(_f())
    assert r.severity is Severity.from_score(r.cvss_score)


def test_scorer_ranked_findings_mutates_and_sorts():
    scorer = TriageScorer()
    low = _f(id="F-7", category="jailbreak", technique_id="jailbreak",
             title="jailbreak", blast_radius="single-user")
    high = _f(id="F-8")
    ranked = scorer.ranked_findings([low, high])
    assert ranked[0].id == "F-8"
    assert ranked[0].cvss_score > 0
    assert low.cvss_score > 0  # mutated in place


def test_scorer_rationale_is_explained():
    r = TriageScorer().score(_f())
    assert any("cross-tenant" in x for x in r.rationale)


# --- reports --------------------------------------------------------------- #

def _reportable(**kw) -> Finding:
    f = _f(**kw)
    f.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
    f.cvss_score = 9.9
    f.severity = Severity.CRITICAL
    f.description = "The memory endpoint ignores tenant ownership."
    f.impact = "Any tenant can read another tenant's history."
    f.expected = "403 for another tenant's conversation."
    f.actual = "HTTP 200 with the victim's history."
    f.remediation = "Scope lookups by authenticated tenant_id."
    f.affected_asset = "api.acme.com/v1/assistant/memory"
    f.observations = [
        Observation(kind="http", request="GET /v1/assistant/memory?id=victim",
                    response="200 OK [REDACTED:email]", status=200,
                    url="api.acme.com", method="GET", redactions=1, sha256="ab" * 32)
    ]
    return f


def test_report_validate_flags_missing_fields():
    f = Finding(id="F-x", title="", technique_id="t", target="a.com", category="jailbreak")
    v = ReportGenerator().validate(f)
    assert not v.ok
    assert "title" in v.missing
    assert "impact" in v.missing


def test_report_validate_passes_for_complete_finding():
    v = ReportGenerator().validate(_reportable())
    assert v.ok, v.missing


def test_report_render_has_all_platform_sections():
    rep = ReportGenerator("hackerone", program="acme").render(_reportable())
    for section in ["Summary", "Affected Asset", "Severity", "Steps To Reproduce",
                    "Expected Result", "Actual Result", "Impact", "Remediation",
                    "Supporting Material"]:
        assert section in rep.markdown


def test_report_bugcrowd_uses_priority_labels():
    rep = ReportGenerator("bugcrowd", program="acme").render(_reportable())
    assert "Reproduction Steps" in rep.markdown
    assert "Observed Behaviour" in rep.markdown


def test_report_strict_raises_when_incomplete():
    f = Finding(id="F-y", title="", technique_id="t", target="a.com", category="jailbreak")
    with pytest.raises(Exception):
        ReportGenerator().render(f, strict=True)


def test_report_structured_payload_matches_submission_contract():
    rep = ReportGenerator("hackerone", program="acme").render(_reportable())
    s = rep.structured
    assert s["affected_asset"] == "api.acme.com/v1/assistant/memory"
    assert s["severity"] == "critical"
    assert s["validation"]["ok"] is True
    assert s["evidence_count"] == 1


def test_report_writes_markdown_and_json(tmp_path):
    gen = ReportGenerator("hackerone", program="acme")
    f = _reportable()
    paths = gen.write(gen.render(f), str(tmp_path / "reports"))
    assert (tmp_path / "reports" / f"{f.id}.md").exists()
    assert (tmp_path / "reports" / f"{f.id}.json").exists()


def test_report_json_is_a_submission_payload(tmp_path):
    import json
    gen = ReportGenerator("hackerone", program="acme")
    f = _reportable()
    gen.write(gen.render(f), str(tmp_path / "r"))
    payload = json.loads((tmp_path / "r" / f"{f.id}.json").read_text())
    assert "vulnerability_information" in payload
    assert payload["report_meta"]["finding_id"] == f.id


def test_report_draft_flag_when_incomplete():
    f = _reportable()
    f.impact = ""
    rep = ReportGenerator().render(f)
    assert "DRAFT" in rep.markdown


# --- dedupe ---------------------------------------------------------------- #

def test_dedup_marks_first_as_new_and_second_as_duplicate(tmp_path):
    reg = DedupRegistry(str(tmp_path / "registry.json"))
    f1 = _f(id="F-10")
    f2 = _f(id="F-11")  # same fingerprint
    assert reg.register(f1) is DedupVerdict.NEW
    assert reg.register(f2) is DedupVerdict.DUPLICATE
    assert f2.status == "duplicated"


def test_dedup_persists_across_instances(tmp_path):
    path = str(tmp_path / "registry.json")
    reg = DedupRegistry(path)
    reg.register(_f(id="F-12"))

    reg2 = DedupRegistry(path)
    assert reg2.check(_f(id="F-13")) is DedupVerdict.DUPLICATE


def test_dedup_imports_known_issues(tmp_path):
    reg = DedupRegistry(str(tmp_path / "registry.json"))
    n = reg.import_known_issues([
        {"id": "known-1", "title": "System prompt leak",
         "category": "system_prompt_leak", "target": "api.acme.com",
         "technique_id": "system_prompt_leak"},
    ])
    assert n == 1
    f = Finding(id="F-14", title="System prompt leak", technique_id="system_prompt_leak",
                target="api.acme.com", category="system_prompt_leak")
    assert reg.check(f) is DedupVerdict.DUPLICATE


def test_dedup_retest_records_and_marks_fixed(tmp_path):
    reg = DedupRegistry(str(tmp_path / "registry.json"))
    f = _f(id="F-15")
    reg.register(f)
    entry = reg.mark_retest("F-15", still_reproduces=False, note="patched")
    assert entry is not None
    assert entry.status == "fixed"
    assert entry.retests[0]["still_reproduces"] is False


def test_dedup_retest_unknown_finding_returns_none(tmp_path):
    reg = DedupRegistry(str(tmp_path / "registry.json"))
    assert reg.mark_retest("nope", still_reproduces=True) is None


def test_dedup_summary(tmp_path):
    reg = DedupRegistry(str(tmp_path / "registry.json"))
    reg.register(_f(id="F-16"))
    reg.mark_retest("F-16", still_reproduces=False)
    s = reg.summary()
    assert s["total"] == 1 and s["fixed"] == 1
