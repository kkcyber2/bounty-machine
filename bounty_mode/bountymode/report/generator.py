"""Report generation — HackerOne / Bugcrowd shaped submissions.

A finding only earns money when a triager accepts it.  Triagers reject reports
that are missing impact, missing reproduction steps, or missing a clear
affected asset.  This module therefore:

1. **Validates** the finding against a required-field contract and reports
   exactly what is missing (rather than silently emitting a weak report).
2. **Renders** a Markdown writeup using the platform's expected section
   headers, in the order triagers read them.
3. **Emits structured JSON** for tooling / API submission.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from ..errors import ReportError
from ..models import Finding, Severity

#: Fields a report cannot be submitted without.
REQUIRED_FIELDS = [
    ("title", "concise, specific title"),
    ("affected_asset", "the exact asset (host/endpoint) affected"),
    ("description", "what the vulnerability is"),
    ("impact", "concrete security/business impact"),
    ("remediation", "how to fix it"),
]

PLATFORM_TEMPLATES = {
    "hackerone": {
        "sections": [
            "Summary",
            "Affected Asset",
            "Severity",
            "Steps To Reproduce",
            "Expected Result",
            "Actual Result",
            "Impact",
            "Remediation",
            "Supporting Material",
        ],
        "severity_labels": {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "informational": "None",
        },
    },
    "bugcrowd": {
        "sections": [
            "Summary",
            "Affected Asset",
            "Severity",
            "Reproduction Steps",
            "Expected Behaviour",
            "Observed Behaviour",
            "Impact",
            "Remediation Advice",
            "Evidence",
        ],
        "severity_labels": {
            "critical": "P1",
            "high": "P2",
            "medium": "P3",
            "low": "P4",
            "informational": "P5",
        },
    },
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ValidationResult:
    ok: bool
    missing: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "missing": self.missing, "warnings": self.warnings}


@dataclass
class RenderedReport:
    finding_id: str
    platform: str
    title: str
    severity: str
    markdown: str
    structured: Dict[str, Any]
    generated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "platform": self.platform,
            "title": self.title,
            "severity": self.severity,
            "markdown": self.markdown,
            "structured": self.structured,
            "generated_at": self.generated_at,
        }


class ReportGenerator:
    """Render findings into submittable reports."""

    def __init__(self, platform: str = "hackerone", program: str = "") -> None:
        key = (platform or "hackerone").strip().lower()
        if key not in PLATFORM_TEMPLATES:
            key = "hackerone"
        self.platform = key
        self.template = PLATFORM_TEMPLATES[key]
        self.program = program

    # -- validation -------------------------------------------------------- #

    def validate(self, finding: Finding) -> ValidationResult:
        missing: List[str] = []
        for attr, _desc in REQUIRED_FIELDS:
            if not str(getattr(finding, attr, "") or "").strip():
                missing.append(attr)

        warnings: List[str] = []
        if not finding.reproducible:
            warnings.append("finding is not marked reproducible — expect a triage push-back")
        if not finding.observations:
            warnings.append("no evidence observations attached")
        if finding.cvss_score <= 0:
            warnings.append("CVSS score is zero — run the triage scorer first")
        if finding.severity in (Severity.CRITICAL, Severity.HIGH) and not finding.observations:
            warnings.append("high severity without evidence is routinely rejected")

        return ValidationResult(ok=not missing, missing=missing, warnings=warnings)

    # -- rendering --------------------------------------------------------- #

    def render(self, finding: Finding, *, strict: bool = False) -> RenderedReport:
        v = self.validate(finding)
        if strict and not v.ok:
            raise ReportError(
                f"finding {finding.id} is missing required fields: {', '.join(v.missing)}"
            )

        sev_label = self.template["severity_labels"].get(finding.severity.value, finding.severity.value)
        md = self._render_markdown(finding, sev_label, v)
        structured = self._render_structured(finding, sev_label, v)

        return RenderedReport(
            finding_id=finding.id,
            platform=self.platform,
            title=finding.title,
            severity=finding.severity.value,
            markdown=md,
            structured=structured,
        )

    def render_many(self, findings: List[Finding], *, strict: bool = False) -> List[RenderedReport]:
        return [self.render(f, strict=strict) for f in findings]

    def write(self, report: RenderedReport, directory: str) -> Dict[str, str]:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        md_path = d / f"{report.finding_id}.md"
        json_path = d / f"{report.finding_id}.json"
        md_path.write_text(report.markdown, encoding="utf-8")
        # The JSON artifact is the *submission payload* itself, with a small
        # metadata envelope — so a tool can POST it without unwrapping.
        payload = dict(report.structured)
        payload["report_meta"] = {
            "finding_id": report.finding_id,
            "platform": report.platform,
            "title": report.title,
            "severity": report.severity,
            "generated_at": report.generated_at,
        }
        json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return {"markdown": str(md_path), "json": str(json_path)}

    # -- internals --------------------------------------------------------- #

    def _render_markdown(self, f: Finding, sev_label: str, v: ValidationResult) -> str:
        steps = self._repro_steps(f)
        evidence = self._evidence_block(f)
        tags = ", ".join(
            filter(None, [
                f"`{f.category}`" if f.category else "",
                *[f"`{c}`" for c in f.cwe],
                *[f"`{o}`" for o in f.owasp_llm],
                *[f"`{m}`" for m in f.mitre_atlas],
            ])
        ) or "—"

        missing_note = ""
        if not v.ok:
            missing_note = (
                "\n> ⚠️ **DRAFT — not submittable yet.** Missing: "
                + ", ".join(v.missing)
                + "\n"
            )
        warn_note = ""
        if v.warnings:
            warn_note = "\n> Reviewer warnings:\n" + "\n".join(f"> - {w}" for w in v.warnings) + "\n"

        parts = [
            f"# {f.title}",
            "",
            f"**Program:** {self.program or '—'}  ",
            f"**Platform:** {self.platform}  ",
            f"**Severity:** {sev_label} ({f.severity.value})  ",
            f"**CVSS v3.1:** `{f.cvss_vector}` — **{f.cvss_score:.1f}**  ",
            f"**Finding ID:** `{f.id}`  ",
            f"**Fingerprint:** `{f.fingerprint}`  ",
            f"**Tags:** {tags}",
            missing_note,
            warn_note,
            "",
            "## Summary",
            f.description or "_No description provided._",
            "",
            "## Affected Asset",
            f"`{f.affected_asset or 'unknown'}`",
            "",
            "## Severity",
            f"- **Rating:** {sev_label} ({f.severity.value})",
            f"- **CVSS v3.1 vector:** `{f.cvss_vector}`",
            f"- **Base score:** {f.cvss_score:.1f}",
            f"- **Blast radius:** {f.blast_radius}",
            f"- **Privileges required:** {f.privileges_required}",
            f"- **User interaction:** {f.user_interaction}",
            f"- **Reproduction rate:** {f.reproduction_rate:.0%} across attempts",
            "",
            "## " + ("Steps To Reproduce" if self.platform == "hackerone" else "Reproduction Steps"),
            steps,
            "",
            "## Expected Result" if self.platform == "hackerone" else "## Expected Behaviour",
            f.expected or "_The application should have refused the request / withheld the data._",
            "",
            "## Actual Result" if self.platform == "hackerone" else "## Observed Behaviour",
            f.actual or "_The application returned data / executed an action it should not have._",
            "",
            "## Impact",
            f.impact or "_Impact not articulated — a report without impact is normally rejected._",
            "",
            "## Remediation" if self.platform == "hackerone" else "## Remediation Advice",
            f.remediation or "_No remediation suggested._",
            "",
            "## Supporting Material" if self.platform == "hackerone" else "## Evidence",
            evidence,
            "",
            "---",
            f"_Generated by Bounty Mode at {_now_iso()}. Evidence has been redacted; "
            "secrets and personal data are replaced with `[REDACTED:*]` markers._",
        ]
        return "\n".join(parts)

    def _repro_steps(self, f: Finding) -> str:
        if f.observations:
            lines = []
            for i, o in enumerate(f.observations, 1):
                head = f"{i}. Send the following to `{o.url or f.affected_asset}`"
                if o.method:
                    head += f" using `{o.method}`"
                lines.append(head + ":")
                if o.request:
                    lines.append("")
                    lines.append("   ```http")
                    for ln in o.request.splitlines()[:20]:
                        lines.append(f"   {ln}")
                    lines.append("   ```")
                if o.response:
                    lines.append("")
                    lines.append("   Observed response (truncated):")
                    lines.append("")
                    lines.append("   ```")
                    for ln in o.response.splitlines()[:12]:
                        lines.append(f"   {ln}")
                    lines.append("   ```")
            return "\n".join(lines)
        if f.technique_id:
            return (
                f"1. Authenticate to `{f.affected_asset}` as a normal user.\n"
                f"2. Replay the `{f.technique_id}` payload captured in the evidence bundle.\n"
                f"3. Observe the response described under **Actual Result**."
            )
        return "_No reproduction steps recorded — this report is not submittable._"

    def _evidence_block(self, f: Finding) -> str:
        if not f.observations:
            return "_No evidence attached._"
        lines = ["| # | Kind | Status | Redactions | SHA-256 |", "|---|------|--------|-----------|---------|"]
        for i, o in enumerate(f.observations, 1):
            lines.append(
                f"| {i} | {o.kind} | {o.status if o.status is not None else '—'} | "
                f"{o.redactions} | `{(o.sha256 or '—')[:16]}` |"
            )
        return "\n".join(lines)

    def _render_structured(self, f: Finding, sev_label: str, v: ValidationResult) -> Dict[str, Any]:
        return {
            "title": f.title,
            "vulnerability_information": f.description,
            "severity": f.severity.value,
            "severity_label": sev_label,
            "cvss_vector": f.cvss_vector,
            "cvss_score": f.cvss_score,
            "affected_asset": f.affected_asset,
            "impact": f.impact,
            "remediation": f.remediation,
            "steps_to_reproduce": self._repro_steps(f),
            "expected": f.expected,
            "actual": f.actual,
            "category": f.category,
            "technique_id": f.technique_id,
            "cwe": f.cwe,
            "owasp_llm": f.owasp_llm,
            "mitre_atlas": f.mitre_atlas,
            "fingerprint": f.fingerprint,
            "evidence_count": len(f.observations),
            "validation": v.to_dict(),
            "platform": self.platform,
            "program": self.program,
            "generated_at": _now_iso(),
        }
