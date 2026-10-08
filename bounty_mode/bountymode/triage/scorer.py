"""Triage / severity scorer.

Answers the question a triager asks first: *how bad is this, really?*

The scorer builds a CVSS v3.1 vector from the finding's real properties
(privileges required, user interaction, blast radius, confidentiality /
integrity / availability impact) and then applies **bounty-specific
adjustments** on top, because platform triage does not weight all findings
equally:

* a **cross-tenant** leak is far more valuable than a single-tenant one;
* a **one-off jailbreak** is usually informational unless it yields data;
* a finding with **no reproduction** is downgraded hard;
* a finding the target's own filter already blocks is downgraded.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from ..models import Finding, Severity
from .cvss import CVSSv31

#: Categories and the impact they normally reach.
_CATEGORY_IMPACT: Dict[str, Dict[str, str]] = {
    "prompt_injection":      {"C": "H", "I": "H", "A": "N", "PR": "N", "UI": "N"},
    "indirect_injection":    {"C": "H", "I": "H", "A": "N", "PR": "N", "UI": "R"},
    "data_exfiltration":     {"C": "H", "I": "N", "A": "N", "PR": "N", "UI": "N"},
    "system_prompt_leak":    {"C": "L", "I": "N", "A": "N", "PR": "N", "UI": "N"},
    "rag_poisoning":         {"C": "H", "I": "H", "A": "N", "PR": "N", "UI": "R"},
    "context_manipulation":  {"C": "L", "I": "L", "A": "N", "PR": "N", "UI": "N"},
    "tool_misuse":           {"C": "H", "I": "H", "A": "L", "PR": "L", "UI": "N"},
    "excessive_agency":      {"C": "H", "I": "H", "A": "L", "PR": "L", "UI": "N"},
    "access_control":        {"C": "H", "I": "H", "A": "N", "PR": "L", "UI": "N"},
    "cross_tenant":          {"C": "H", "I": "H", "A": "N", "PR": "L", "UI": "N"},
    "jailbreak":             {"C": "L", "I": "L", "A": "N", "PR": "N", "UI": "N"},
    "output_handling":       {"C": "H", "I": "H", "A": "N", "PR": "N", "UI": "R"},
    "multimodal_injection":  {"C": "H", "I": "H", "A": "N", "PR": "N", "UI": "R"},
    "supply_chain":          {"C": "H", "I": "H", "A": "H", "PR": "N", "UI": "R"},
    "economic_denial":       {"C": "N", "I": "N", "A": "H", "PR": "N", "UI": "N"},
}

_BLAST_SCOPE = {
    "single-user": "U",
    "multi-user": "U",
    "cross-tenant": "C",
    "system": "C",
}


@dataclass
class TriageResult:
    severity: Severity
    cvss_score: float
    cvss_vector: str
    priority: int  # 0 = drop, higher = submit first
    rationale: List[str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "priority": self.priority,
            "rationale": self.rationale,
        }


class TriageScorer:
    """Rank findings by real impact."""

    def __init__(self, *, min_score_to_submit: float = 4.0) -> None:
        self.min_score_to_submit = min_score_to_submit

    def score(self, finding: Finding) -> TriageResult:
        rationale: List[str] = []

        impact = _CATEGORY_IMPACT.get(finding.category, _CATEGORY_IMPACT["context_manipulation"])
        vec = CVSSv31(
            AV="N",
            AC="L" if finding.reproducible else "H",
            PR={"none": "N", "low": "L", "high": "H"}.get(finding.privileges_required, "N"),
            UI="R" if finding.user_interaction == "required" else "N",
            S=_BLAST_SCOPE.get(finding.blast_radius, "U"),
            C=impact["C"],
            I=impact["I"],
            A=impact["A"],
        )
        score = vec.base_score()

        # --- adjustments --------------------------------------------------- #
        if finding.blast_radius == "cross-tenant":
            score = min(10.0, score + 0.5)
            rationale.append("cross-tenant blast radius (+0.5)")
        elif finding.blast_radius == "system":
            score = min(10.0, score + 0.7)
            rationale.append("system-wide blast radius (+0.7)")

        if not finding.reproducible:
            score = max(0.0, score - 2.5)
            rationale.append("not reproducibly verified (-2.5)")
        elif finding.reproduction_rate and finding.reproduction_rate < 0.5:
            score = max(0.0, score - 1.0)
            rationale.append(f"low reproduction rate {finding.reproduction_rate:.0%} (-1.0)")

        if finding.confidence < 0.5:
            score = max(0.0, score - 1.0)
            rationale.append(f"low confidence {finding.confidence:.0%} (-1.0)")

        if finding.category == "jailbreak" and impact["C"] == "L":
            rationale.append("plain jailbreak with no data impact — typically informational")

        # informational classes can never be promoted above LOW
        if finding.category in {"system_prompt_leak", "jailbreak"} and impact["C"] == "L":
            score = min(score, 3.9)

        score = round(score, 1)
        severity = Severity.from_score(score)

        priority = 0
        if score >= self.min_score_to_submit and finding.reproducible:
            priority = int(score * 10) + (5 if finding.blast_radius == "cross-tenant" else 0)
            rationale.append("meets submission bar (reproducible + score >= threshold)")
        else:
            if not finding.reproducible:
                rationale.append("dropped: no reproducible PoC")
            else:
                rationale.append(f"dropped: score {score} below submit threshold {self.min_score_to_submit}")

        return TriageResult(
            severity=severity,
            cvss_score=score,
            cvss_vector=vec.vector(),
            priority=priority,
            rationale=rationale,
        )

    def score_all(self, findings: List[Finding]) -> List[TriageResult]:
        """Score and *mutate* each finding with its computed severity/CVSS,
        returning results in submission priority order."""
        results: List[TriageResult] = []
        for f in findings:
            r = self.score(f)
            f.severity = r.severity
            f.cvss_score = r.cvss_score
            f.cvss_vector = r.cvss_vector
            results.append(r)
        order = sorted(range(len(findings)), key=lambda i: results[i].priority, reverse=True)
        return [results[i] for i in order]

    def ranked_findings(self, findings: List[Finding]) -> List[Finding]:
        """Return findings sorted for submission (highest priority first)."""
        scored = [(f, self.score(f)) for f in findings]
        for f, r in scored:
            f.severity = r.severity
            f.cvss_score = r.cvss_score
            f.cvss_vector = r.cvss_vector
        scored.sort(key=lambda fr: fr[1].priority, reverse=True)
        return [f for f, _ in scored]
