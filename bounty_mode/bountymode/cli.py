"""Bounty Mode command-line interface.

A single, discoverable entry point.  Everything an operator needs to go from a
program policy to a submittable report:

    bountymode scope import policy.md --program acme -o scope.json
    bountymode techniques
    bountymode check scope.json api.acme.com --technique prompt_injection
    bountymode run case.yaml                 # dry run (no engine calls)
    bountymode run case.yaml --live --engine https://engine --token $TOKEN
    bountymode triage findings.json -o triaged.json
    bountymode report triaged.json --platform hackerone -o out/

Safety default: ``run`` performs a **dry run** unless ``--live`` is passed.
A dry run exercises the gate, the vault and the scorer without contacting a
target, which is the right way to validate a case file before arming it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .authority.gate import Approval, AuthorizationGate
from .authority.stop_conditions import StopConditionEngine, StopConditions
from .dedupe.registry import DedupRegistry
from .evidence.redactor import Redactor
from .evidence.vault import EvidenceVault
from .models import Finding, ProgramScope, Technique
from .report.generator import ReportGenerator
from .runner.adapter import AgathonAdapter, EngineResult, TechniqueRegistry
from .runner.case_runner import CaseRunner
from .scope.importer import ScopeImporter
from .triage.scorer import TriageScorer

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_BLOCKED = 3


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _load_yaml_or_json(path: str) -> Dict[str, Any]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        return json.loads(text)
    try:
        import yaml # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "PyYAML is required for YAML case files. Install it or use JSON."
        ) from exc
    return yaml.safe_load(text)


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def _load_scope(path: str) -> ProgramScope:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ProgramScope.from_dict(data)


def _load_findings(path: str) -> List[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    return [Finding.from_dict(f) for f in data]


def _technique_from_dict(raw: Any) -> Technique:
    if isinstance(raw, str):
        return TechniqueRegistry().require(raw)
    if isinstance(raw, dict):
        return Technique.from_dict(raw)
    raise ValueError(f"bad technique entry: {raw!r}")


# --------------------------------------------------------------------------- #
# command implementations
# --------------------------------------------------------------------------- #

def cmd_scope_import(args: argparse.Namespace) -> int:
    importer = ScopeImporter()
    scope = importer.import_file(args.policy, program=args.program)
    out = args.output or f"{scope.program}-scope.json"
    importer.export(scope, out)
    print(f"Imported program '{scope.program}' ({scope.platform}).")
    print(f"  in-scope assets : {len(scope.in_scope)}")
    print(f"  exclusions      : {len(scope.out_of_scope)}")
    print(f"  prohibited      : {', '.join(scope.prohibited_techniques) or '—'}")
    print(f"  rate limit      : {scope.rate_limit_rps:.3f} req/s, max {scope.max_requests} requests")
    print(f"  wrote           : {out}")
    if importer.warnings:
        print("\nWarnings:")
        for w in importer.warnings:
            print(f"  ! {w}")
    print("\nReview this file before running any test.")
    return EXIT_OK


def cmd_scope_show(args: argparse.Namespace) -> int:
    scope = _load_scope(args.scope)
    _print(scope.to_dict())
    return EXIT_OK


def cmd_techniques(args: argparse.Namespace) -> int:
    reg = TechniqueRegistry()
    rows = []
    for t in reg.all():
        rows.append(
            {
                "id": t.id,
                "category": t.category,
                "severity_hint": t.severity_hint,
                "destructive": t.destructive,
                "side_effects": t.side_effects,
                "engine_key": t.engine_key,
            }
        )
    _print({"count": len(rows), "techniques": rows})
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    scope = _load_scope(args.scope)
    gate = AuthorizationGate(scope)
    reg = TechniqueRegistry()
    techniques = [_technique_from_dict(t) for t in args.technique] if args.technique else reg.all()
    results = []
    for t in techniques:
        d = gate.authorize(args.target, t)
        results.append(
            {"technique": t.id, "verdict": d.verdict.value, "reason": d.reason,
             "matched_scope": d.matched_scope}
        )
    _print({"target": args.target, "summary": gate.summary(), "decisions": results})
    return EXIT_OK if any(r["verdict"] == "allow" for r in results) else EXIT_BLOCKED


def cmd_run(args: argparse.Namespace) -> int:
    case = _load_yaml_or_json(args.case)
    scope_path = args.scope or case.get("scope")
    if not scope_path:
        print("error: no scope. Pass --scope or set 'scope' in the case file.", file=sys.stderr)
        return EXIT_USAGE
    scope = _load_scope(scope_path)

    target = case.get("target")
    if not target:
        print("error: case file must set 'target'.", file=sys.stderr)
        return EXIT_USAGE

    technique_ids = case.get("techniques") or []
    if not technique_ids:
        print("error: case file must list 'techniques'.", file=sys.stderr)
        return EXIT_USAGE

    out_dir = Path(args.output or case.get("output_dir", "bounty-run"))
    out_dir.mkdir(parents=True, exist_ok=True)

    gate = AuthorizationGate(scope)
    for appr in case.get("approvals", []) or []:
        gate.register_approval(
            Approval(
                target=appr.get("target", target),
                technique_id=appr["technique"],
                approved_by=appr.get("approved_by", "unknown"),
                approved_at=appr.get("approved_at", ""),
                note=appr.get("note", ""),
            )
        )

    stops = StopConditionEngine(StopConditions.from_scope(scope))
    vault = EvidenceVault(str(out_dir / "evidence"), redactor=Redactor())
    dedup = DedupRegistry(str(out_dir / "registry.json"))

    dispatch = None
    live = bool(args.live)
    if live:
        if not args.engine:
            print("error: --live requires --engine <url>.", file=sys.stderr)
            return EXIT_USAGE
        adapter = AgathonAdapter(args.engine, token=args.token or "")

        def dispatch(t: Technique, tgt: str) -> EngineResult:  # noqa: E306
            return adapter.run_test(t, tgt)

    runner = CaseRunner(
        gate=gate,
        stops=stops,
        vault=vault,
        dedup=dedup,
        dispatch=dispatch,
    )

    print(f"Case '{case.get('id', 'case')}' against {target}")
    print(f"Mode: {'LIVE' if live else 'DRY RUN (no engine calls)'}")
    print(f"Scope: {scope.program}  |  techniques: {len(technique_ids)}\n")

    result = runner.run(case.get("id", "case"), scope, target, technique_ids)
    runner.write_result(result, str(out_dir / "result.json"))

    print(f"requests made : {result.requests_made}")
    print(f"findings      : {len(result.findings)}")
    print(f"skipped       : {len(result.skipped)}")
    print(f"errors        : {len(result.errors)}")
    if result.stopped:
        print(f"STOPPED       : {result.stop_reason}")
    for s in result.skipped:
        print(f"  - skipped {s['technique']}: {s['reason']}")
    for f in result.findings:
        print(f"  + {f.severity.value.upper():<13} {f.title}  (cvss {f.cvss_score<:.1f})")
    print(f"\nArtifacts under: {out_dir}")
    return EXIT_OK


def cmd_triage(args: argparse.Namespace) -> int:
    findings = _load_findings(args.findings)
    scorer = TriageScorer(min_score_to_submit=args.min_score)
    ranked = scorer.ranked_findings(findings)
    out = args.output or args.findings
    Path(out).write_text(
        json.dumps([f.to_dict() for f in ranked], indent=2, sort_keys=True), encoding="utf-8"
    )
    for f in ranked:
        submittable = f.cvss_score >= args.min_score and f.reproducible
        print(
            f"{'SUBMIT' if submittable else 'DROP  '}  {f.severity.value.upper():<13} "
            f"cvss {f.cvss_score:>4.1f}  {f.title}"
        )
    print(f"\nWrote {len(ranked)} scored findings to {out}")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    findings = _load_findings(args.findings)
    gen = ReportGenerator(platform=args.platform, program=args.program or "")
    out_dir = Path(args.output or "reports")
    written = 0
    for f in findings:
        v = gen.validate(f)
        if not v.ok and args.require_valid:
            print(f"skip {f.id}: missing {', '.join(v.missing)}")
            continue
        rep = gen.render(f, strict=False)
        paths = gen.write(rep, str(out_dir))
        written += 1
        print(f"{'OK ' if v.ok else 'DRAFT'} {f.id} -> {paths['markdown']}")
    print(f"\n{written} report(s) written to {out_dir}")
    return EXIT_OK


def cmd_retest(args: argparse.Namespace) -> int:
    registry = DedupRegistry(args.registry)
    f = registry.mark_retest(args.finding_id, still_reproduces=not args.fixed, note=args.note or "")
    if f is None:
        print(f"finding {args.finding_id} not found in {args.registry}", file=sys.stderr)
        return EXIT_USAGE
    print(f"{f.finding_id}: {'STILL REPRODUCES — escalate' if not args.fixed else 'FIXED — close'}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bountymode",
        description="Authorized AI bug-bounty workflow: scope, gate, evidence, triage, report.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scope", help="import and inspect a program scope")
    ssub = s.add_subparsers(dest="scope_command", required=True)
    si = ssub.add_parser("import", help="import a policy file into a scope JSON")
    si.add_argument("policy")
    si.add_argument("--program", default=None)
    si.add_argument("-o", "--output", default=None)
    si.set_defaults(func=cmd_scope_import)
    ss = ssub.add_parser("show", help="print a scope JSON")
    ss.add_argument("scope")
    ss.set_defaults(func=cmd_scope_show)

    t = sub.add_parser("techniques", help="list the technique catalogue")
    t.set_defaults(func=cmd_techniques)

    c = sub.add_parser("check", help="dry-run the authorization gate for a target")
    c.add_argument("scope")
    c.add_argument("target")
    c.add_argument("--technique", action="append", default=None)
    c.set_defaults(func=cmd_check)

    r = sub.add_parser("run", help="run a case (dry run unless --live)")
    r.add_argument("case")
    r.add_argument("--scope", default=None)
    r.add_argument("-o", "--output", default=None)
    r.add_argument("--live", action="store_true", help="actually dispatch to the engine")
    r.add_argument("--engine", default=None, help="engine base URL (required with --live)")
    r.add_argument("--token", default=None, help="internal scan token")
    r.set_defaults(func=cmd_run)

    tr = sub.add_parser("triage", help="score findings and rank them")
    tr.add_argument("findings")
    tr.add_argument("-o", "--output", default=None)
    tr.add_argument("--min-score", type=float, default=4.0)
    tr.set_defaults(func=cmd_triage)

    rp = sub.add_parser("report", help="render submission reports")
    rp.add_argument("findings")
    rp.add_argument("--platform", default="hackerone", choices=["hackerone", "bugcrowd"])
    rp.add_argument("--program", default=None)
    rp.add_argument("-o", "--output", default="reports")
    rp.add_argument("--require-valid", action="store_true",
                    help="skip findings that are missing required fields")
    rp.set_defaults(func=cmd_report)

    rt = sub.add_parser("retest", help="record a regression retest")
    rt.add_argument("finding_id")
    rt.add_argument("--registry", default="registry.json")
    rt.add_argument("--fixed", action="store_true", help="the finding no longer reproduces")
    rt.add_argument("--note", default=None)
    rt.set_defaults(func=cmd_retest)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
