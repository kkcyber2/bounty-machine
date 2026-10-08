"""CVSS v3.1 base score.

A dependency-free implementation of the CVSS v3.1 base metric group, so a
finding's severity is computed the same way a triager's calculator would —
rather than the pseudo-CVSS the original engine produced.

Reference: FIRST CVSS v3.1 specification (base score equations).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict, Optional

# Metric -> {value: weight}
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}   # scope changed
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_METRIC_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

_VECTOR_RE = re.compile(r"CVSS:3\.[01]/(?:[A-Z]{1,2}:[A-Z]+)(?:/[A-Z]{1,2}:[A-Z]+)+", re.I)


@dataclass
class CVSSv31:
    """CVSS v3.1 base metrics."""

    AV: str = "N"  # Attack Vector
    AC: str = "L"  # Attack Complexity
    PR: str = "N"  # Privileges Required
    UI: str = "N"  # User Interaction
    S: str = "U"   # Scope
    C: str = "H"   # Confidentiality
    I: str = "N"   # Integrity
    A: str = "N"   # Availability

    def vector(self) -> str:
        body = "/".join(f"{m}:{getattr(self, m)}" for m in _METRIC_ORDER)
        return f"CVSS:3.1/{body}"

    def base_score(self) -> float:
        """Compute the CVSS v3.1 base score, rounded up to one decimal."""
        scope_changed = self.S == "C"
        iss = 1 - (
            (1 - _CIA[self.C]) * (1 - _CIA[self.I]) * (1 - _CIA[self.A])
        )
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        pr = (_PR_C if scope_changed else _PR_U)[self.PR]
        exploitability = 8.22 * _AV[self.AV] * _AC[self.AC] * pr * _UI[self.UI]

        if impact <= 0:
            return 0.0

        if scope_changed:
            raw = min(1.08 * (impact + exploitability), 10.0)
        else:
            raw = min(impact + exploitability, 10.0)

        return _roundup1(raw)

    @classmethod
    def from_vector(cls, vector: str) -> "CVSSv31":
        parts = {}
        for chunk in (vector or "").split("/"):
            if ":" in chunk:
                k, v = chunk.split(":", 1)
                parts[k.upper()] = v.upper()
        kwargs = {m: parts.get(m, getattr(cls(), m)) for m in _METRIC_ORDER}
        return cls(**kwargs)

    def to_dict(self) -> Dict[str, object]:
        return {
            "vector": self.vector(),
            "base_score": self.base_score(),
            "metrics": {m: getattr(self, m) for m in _METRIC_ORDER},
        }


def _roundup1(value: float) -> float:
    """CVSS 'Roundup' to one decimal place (avoids float 0.1 artefacts)."""
    i = int(round(value * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> Optional[CVSSv31]:
    if not vector:
        return None
    if not _VECTOR_RE.search(vector):
        return None
    return CVSSv31.from_vector(vector)


def score_vector(vector: str) -> float:
    parsed = parse_vector(vector)
    return parsed.base_score() if parsed else 0.0
