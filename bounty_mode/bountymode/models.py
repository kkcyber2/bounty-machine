"""Core data models shared by every Bounty Mode module.

Everything here is a plain dataclass with ``to_dict``/``from_dict`` helpers so
that a case file, a captured finding and a rendered report can all round-trip
through JSON with no third-party dependency.

The vocabulary deliberately mirrors how bug-bounty platforms describe work:

``ProgramScope``   what a program allows (the importable policy).
``Technique``      one offensive test we intend to run (a test-case step).
``Finding``        one observed, potentially reportable vulnerability.
``Observation``    the raw request/response pair backing a finding.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict, fields
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    """Platform-aligned severity labels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Map a CVSS 3.1 base score (0-10) to a platform severity label."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Verdict(str, Enum):
    """Outcome of the authorization gate."""

    ALLOW = "allow"
    DENY = "deny"
    NEEDS_HUMAN = "needs_human"


@dataclass
class ScopeTarget:
    """An asset that a program has explicitly placed *in* scope.

    ``pattern`` is a host, host glob (``*.example.com``), URL prefix
    (``https://api.example.com/v1``) or a full URL.  ``kind`` is informational
    (``web``, ``api``, ``llm``, ``mobile``, ``repo``).
    """

    pattern: str
    kind: str = "web"
    notes: str = ""
    max_severity: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OutOfScopeRule:
    """An asset or class of testing a program has explicitly excluded."""

    pattern: str
    reason: str = ""
    kind: str = "host"  # host | url | technique

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProgramScope:
    """A machine-readable representation of one bug-bounty program policy."""

    program: str
    platform: str = "generic"
    in_scope: List[ScopeTarget] = field(default_factory=list)
    out_of_scope: List[OutOfScopeRule] = field(default_factory=list)
    # Technique ids the program forbids outright (e.g. "economic_denial").
    prohibited_techniques: List[str] = field(default_factory=list)
    # Technique ids the program explicitly permits even though they are
    # usually disruptive (rare — most programs never allow these).
    permitted_techniques: List[str] = field(default_factory=list)
    rate_limit_rps: float = 1.0
    max_requests: int = 500
    max_duration_s: int = 1800
    requires_test_account: bool = False
    safe_harbour: bool = True
    disclosure_days: int = 90
    source_url: str = ""
    raw_hash: str = ""
    imported_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["in_scope"] = [t.to_dict() for t in self.in_scope]
        data["out_of_scope"] = [r.to_dict() for r in self.out_of_scope]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProgramScope":
        data = dict(data)

        def _target(e: Any) -> ScopeTarget:
            return ScopeTarget(pattern=e) if isinstance(e, str) else ScopeTarget(**e)

        def _rule(e: Any) -> OutOfScopeRule:
            return OutOfScopeRule(pattern=e) if isinstance(e, str) else OutOfScopeRule(**e)

        data["in_scope"] = [_target(t) for t in data.get("in_scope", [])]
        data["out_of_scope"] = [_rule(r) for r in data.get("out_of_scope", [])]
        data = _drop_unknown(cls, data)
        return cls(**data)


@dataclass
class AuthorizationDecision:
    """The gate's verdict for one (target, technique) pair."""

    target: str
    technique_id: str
    verdict: Verdict
    reason: str
    matched_scope: Optional[str] = None
    matched_exclusion: Optional[str] = None
    human_approved: bool = False
    decided_at: str = field(default_factory=_now_iso)

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data


@dataclass
class Technique:
    """One offensive test-case step.

    ``engine_key`` maps onto the Agathon engine's attack registry
    (``attacks/*.py`` class names / plugin ids).  ``agentic`` marks tests that
    require tool-use / agent behaviour rather than a single prompt.
    """

    id: str
    name: str
    engine_key: str = ""
    category: str = "prompt_injection"
    severity_hint: str = "medium"
    destructive: bool = False
    side_effects: bool = False
    requires_auth: bool = False
    requires_multimodal: bool = False
    description: str = ""
    tags: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Technique":
        return cls(**_drop_unknown(cls, dict(data)))


@dataclass
class Observation:
    """One request/response pair captured as evidence.

    Both fields *should* already be redacted by the vault before persistence;
    ``redactions`` records how many substitutions were made and ``sha256`` is
    a content hash of the redacted bytes for integrity.
    """

    kind: str  # "http" | "prompt" | "response" | "note"
    request: str = ""
    response: str = ""
    status: Optional[int] = None
    url: str = ""
    method: str = "POST"
    captured_at: str = field(default_factory=_now_iso)
    redactions: int = 0
    sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Observation":
        return cls(**_drop_unknown(cls, dict(data)))


@dataclass
class Finding:
    """A single potentially-reportable vulnerability."""

    id: str
    title: str
    technique_id: str
    target: str
    category: str
    severity: Severity = Severity.MEDIUM
    cvss_vector: str = ""
    cvss_score: float = 0.0
    confidence: float = 0.5
    reproducible: bool = False
    reproduction_rate: float = 0.0
    privileges_required: str = "none"  # none | low | high
    user_interaction: str = "none"  # none | required
    blast_radius: str = "single-user"  # single-user | multi-user | cross-tenant | system
    description: str = ""
    impact: str = ""
    expected: str = ""
    actual: str = ""
    remediation: str = ""
    affected_asset: str = ""
    cwe: List[str] = field(default_factory=list)
    owasp_llm: List[str] = field(default_factory=list)
    mitre_atlas: List[str] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    fingerprint: str = ""
    created_at: str = field(default_factory=_now_iso)
    status: str = "new"  # new | triaged | duplicated | reported | fixed | retested

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(
                self.category, self.target, self.technique_id, self.title
            )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["observations"] = [o.to_dict() for o in self.observations]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        data = dict(data)
        data["severity"] = Severity(data.get("severity", "medium"))
        data["observations"] = [Observation.from_dict(o) for o in data.get("observations", [])]
        data = _drop_unknown(cls, data)
        return cls(**data)


def _drop_unknown(dc: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Ignore unknown keys so a hand-edited JSON file never crashes loading."""
    known = {f.name for f in fields(dc)}
    return {k: v for k, v in data.items() if k in known}


_FP_NOISE = re.compile(r"[^a-z0-9]+")


def compute_fingerprint(*parts: str) -> str:
    """Stable, order-preserving fingerprint used for de-duplication.

    Case-folded and stripped of punctuation so ``"System-Prompt Leak"`` and
    ``"system prompt leak"`` collapse to the same bucket.
    """
    normalized = "|".join(_FP_NOISE.sub(" ", (p or "").lower()).strip() for p in parts)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def json_dumps(obj: Any) -> str:
    """Deterministic JSON for hashing and file writes."""

    def _default(o: Any) -> Any:
        if isinstance(o, Enum):
            return o.value
        if hasattr(o, "to_dict"):
            return o.to_dict()  # type: ignore[no-any-return]
        raise TypeError(f"not JSON serializable: {type(o)!r}")

    return json.dumps(obj, indent=2, sort_keys=True, default=_default)
