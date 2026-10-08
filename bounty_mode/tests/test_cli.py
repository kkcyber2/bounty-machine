"""End-to-end test driving the real CLI.

Runs the whole pipeline offline: import a policy, gate a target, run a dry-run
case, score, and render reports — through ``main(argv)`` exactly as a user
would from the shell.
"""

from __future__ import annotations

import json

from bountymode.cli import main

POLICY = """
# Acme AI Bounty Program (HackerOne)

## In Scope
- https://api.acme.com
- chat.acme.com

## Out of Scope
- admin.acme.com

Rules: do not exceed 2 requests per second. Maximum 250 requests.
Safe harbour applies.
"""


def test_cli_full_pipeline(tmp_path, capsys):
    scope_path = tmp_path / "scope.json"
    case_path = tmp_path / "case.yaml"
    out_dir = tmp_path / "run"

    # 1. import
    assert main(["scope", "import", str(_policy(tmp_path)), "--program", "acme",
                 "-o", str(scope_path)]) == 0
    assert scope_path.exists()
    scope = json.loads(scope_path.read_text())
    assert scope["program"] == "acme"
    assert any("api.acme.com" in t["pattern"] for t in scope["in_scope"])

    # 2. show
    assert main(["scope", "show", str(scope_path)]) == 0

    # 3. techniques
    assert main(["techniques"]) == 0

    # 4. check — in scope allowed
    assert main(["check", str(scope_path), "api.acme.com",
                 "--technique", "prompt_injection"]) == 0
    # 5. check — out of scope blocked (exit 3)
    assert main(["check", str(scope_path), "evil.test",
                 "--technique", "prompt_injection"]) == 3

    # 6. run (dry run)
    case_path.write_text(
        "id: demo\n"
        f"scope: {scope_path}\n"
        "target: api.acme.com\n"
        "techniques:\n"
        "  - prompt_injection\n"
        "  - economic_denial\n"
        "  - tool_misuse\n"
    )
    assert main(["run", str(case_path), "-o", str(out_dir)]) == 0
    result = json.loads((out_dir / "result.json").read_text())
    assert result["requests_made"] == 0
    assert len(result["skipped"]) == 3  # dry run: none dispatched


def test_cli_run_without_engine_errors_in_live_mode(tmp_path):
    scope_path = tmp_path / "scope.json"
    case_path = tmp_path / "case.yaml"
    main(["scope", "import", str(_policy(tmp_path)), "--program", "acme", "-o", str(scope_path)])
    case_path.write_text(
        "id: demo\n"
        f"scope: {scope_path}\n"
        "target: api.acme.com\n"
        "techniques:\n"
        "  - prompt_injection\n"
    )
    # --live with no --engine must be a usage error, not a crash
    assert main(["run", str(case_path), "--live"]) == 2


def test_cli_run_missing_scope_is_usage_error(tmp_path):
    case_path = tmp_path / "case.yaml"
    case_path.write_text("id: demo\ntarget: api.acme.com\ntechniques:\n  - prompt_injection\n")
    assert main(["run", str(case_path)]) == 2


def test_cli_triage_and_report(tmp_path):
    findings = [
        {
            "id": "F-1",
            "title": "Cross-tenant conversation disclosure",
            "technique_id": "cross_tenant",
            "target": "api.acme.com",
            "category": "cross_tenant",
            "reproducible": True,
            "reproduction_rate": 1.0,
            "confidence": 0.95,
            "blast_radius": "cross-tenant",
            "privileges_required": "low",
            "description": "The memory endpoint ignores tenant ownership.",
            "impact": "Any tenant can read another tenant's history.",
            "expected": "403.",
            "actual": "200 with the victim's data.",
            "remediation": "Scope by tenant_id.",
            "affected_asset": "api.acme.com/v1/assistant/memory",
        }
    ]
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(findings))
    triaged = tmp_path / "triaged.json"
    reports = tmp_path / "reports"

    assert main(["triage", str(findings_path), "-o", str(triaged)]) == 0
    scored = json.loads(triaged.read_text())
    assert scored[0]["cvss_score"] > 0

    assert main(["report", str(triaged), "--platform", "hackerone",
                 "--program", "acme", "-o", str(reports)]) == 0
    assert (reports / "F-1.md").exists()
    assert (reports / "F-1.json").exists()


def test_cli_retest_updates_registry(tmp_path):
    # build a registry via a triage/report round trip is overkill; use the API
    from bountymode.dedupe.registry import DedupRegistry
    from bountymode.models import Finding

    reg_path = tmp_path / "registry.json"
    reg = DedupRegistry(str(reg_path))
    reg.register(Finding(id="F-99", title="t", technique_id="x", target="a.com",
                         category="jailbreak"))

    assert main(["retest", "F-99", "--registry", str(reg_path), "--fixed"]) == 0
    entry = DedupRegistry(str(reg_path)).get("F-99")
    assert entry is not None and entry.status == "fixed"


def _policy(tmp_path):
    p = tmp_path / "policy.md"
    p.write_text(POLICY)
    return p
