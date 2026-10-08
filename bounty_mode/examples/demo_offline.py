#!/usr/bin/env python3
"""Offline end-to-end demo — no network, no API keys, no engine.

Walks the full Bounty Mode pipeline against a fake engine so you can see the
safety behaviour before touching a real program:

    python examples/demo_offline.py

It demonstrates, in order:
  1. importing a program policy into a machine-readable scope
  2. the authorization gate allowing / denying / deferring techniques
  3. a case run where a destructive technique never reaches the engine
  4. evidence capture with automatic secret redaction
  5. triage scoring and ranked output
  6. HackerOne-shaped report rendering
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from bountymode import (
    Approval,
    AuthorizationGate,
    CaseRunner,
    DedupRegistry,
    EngineResult,
    EvidenceVault,
    ReportGenerator,
    ScopeImporter,
    StopConditionEngine,
    StopConditions,
    TechniqueRegistry,
    TriageScorer,
)

POLICY = """
# Demo AI Bounty (HackerOne)
## In Scope
- api.demo.com
## Out of Scope
- admin.demo.com
- Denial of service is prohibited
Maximum 100 requests. 1 request per second.
"""


def banner(text: str) -> None:
    print(f"\n{'=' * 72}\n{text}\n{'=' * 72}")


def main() -> None:
    workdir = Path(tempfile.mkdtemp(prefix="bountymode-demo-"))

    banner("1. Import the program policy")
    importer = ScopeImporter()
    scope = importer.from_text(POLICY, program="demo")
    print(f"program      : {scope.program} ({scope.platform})")
    print(f"in scope     : {[t.pattern for t in scope.in_scope]}")
    print(f"excluded     : {[r.pattern for r in scope.out_of_scope]}")
    print(f"prohibited   : {scope.prohibited_techniques}")

    banner("2. Authorization gate")
    gate = AuthorizationGate(scope)
    gate.register_approval(
        Approval(
            target="api.demo.com",
            technique_id="tool_misuse",
            approved_by="demo-analyst",
            approved_at="2026-10-08T00:00:00Z",
        )
    )
    registry = TechniqueRegistry()
    for tid in ["prompt_injection", "economic_denial", "tool_misuse"]:
        d = gate.authorize("api.demo.com", registry.require(tid))
        print(f"  {tid:<20} -> {d.verdict.value.upper():<11} {d.reason}")
    d = gate.authorize("evil.example", registry.require("prompt_injection"))
    print(f"  {'out-of-scope target':<20} -> {d.verdict.value.upper():<11} {d.reason}")

    banner("3. Case run (fake engine; secrets in the payload)")
    calls: list = []

    def fake_engine(technique, target) -> EngineResult:
        calls.append(technique.id)
        if technique.id == "data_exfiltration":
            return EngineResult(
                technique.id, target, success=True, success_score=0.94,
                payload_used='{"api_key": "sk-demo-0000000000000000"}',
                response="sure: sk-demo-0000000000000000 and admin@demo.com",
                evidence="model returned the injected secret",
                vulnerability_type="data_exfiltration", target_model="demo-model",
            )
        return EngineResult(technique.id, target, success=False, evidence="no hit")

    runner = CaseRunner(
        gate=gate,
        stops=StopConditionEngine(StopConditions.from_scope(scope)),
        vault=EvidenceVault(str(workdir / "evidence")),
        dedup=DedupRegistry(str(workdir / "registry.json")),
        dispatch=fake_engine,
    )
    result = runner.run(
        "demo-pass", scope, "api.demo.com",
        ["prompt_injection", "economic_denial", "data_exfiltration", "tool_misuse"],
    )
    print(f"engine calls : {calls}  <- 'economic_denial' is absent: it was blocked")
    print(f"findings     : {len(result.findings)}")
    for f in result.findings:
        print(f"  + {f.severity.value.upper():<12} {f.title}")

    banner("4. Evidence redaction")
    for f in result.findings:
        for o in f.observations:
            print(f"  redactions applied: {o.redactions}")
            print(f"  request  : {o.request}")
            print(f"  response : {o.response}")
    on_disk = "".join(
        p.read_text(encoding="utf-8") for p in (workdir / "evidence").rglob("*.json")
    )
    print(f"  raw secret present on disk? {'sk-demo-0000000000000000' in on_disk}")
    print(f"  victim email on disk?      {'admin@demo.com' in on_disk}")

    banner("5. Triage + report")
    ranked = TriageScorer().ranked_findings(result.findings)
    for f in ranked:
        print(f"  cvss {f.cvss_score:>4.1f}  {f.severity.value.upper():<13} {f.title}")
    gen = ReportGenerator("hackerone", program="demo")
    for f in ranked:
        rep = gen.render(f)
        print(f"  report: {rep.finding_id} ({'valid' if rep.structured['validation']['ok'] else 'draft'})")
        paths = gen.write(rep, str(workdir / "reports"))
    print(f"\nArtifacts under: {workdir}")


if __name__ == "__main__":
    main()
