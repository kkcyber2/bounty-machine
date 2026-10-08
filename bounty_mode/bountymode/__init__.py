"""
bountymode — authorized AI bug-bounty workflow layer.

Bounty Mode sits *in front of* an offensive AI red-teaming engine (the Agathon
engine) and turns raw attack execution into a submittable, scope-compliant
bug-bounty report.

Design rules
------------
1. Deny by default.  No target may be tested unless it is explicitly in scope
   for an imported program AND an authorization decision has been granted.
2. No destructive actions.  Techniques classified as disruptive (denial of
   service, rate-limit exhaustion) are blocked at the gate even when in scope.
3. Minimal proof of impact.  The evidence vault redacts secrets and PII before
   anything is written to disk or included in a report.
4. Human in the loop.  Any test case marked ``side_effects=True`` requires an
   explicit, audited approval before the gate will pass it.
5. Offline first.  Scope parsing, gating, redaction, scoring, de-duplication
   and report rendering all work with no network access and no API keys.

Quickstart
----------
>>> from bountymode import ScopeImporter, AuthorizationGate, TechniqueRegistry
>>> scope = ScopeImporter().from_dict({
...     "program": "acme", "in_scope": ["api.acme.com"],
...     "out_of_scope": [{"pattern": "admin.acme.com"}],
... })
>>> gate = AuthorizationGate(scope)
>>> tech = TechniqueRegistry().require("prompt_injection")
>>> gate.authorize("api.acme.com", tech).verdict.value
'allow'

See ``README.md`` for the end-to-end workflow.
"""

from .errors import (
    AuthorizationError,
    BountyModeError,
    EvidenceError,
    ReportError,
    ScopeViolationError,
    StopConditionError,
)
from .models import (
    AuthorizationDecision,
    Finding,
    Observation,
    OutOfScopeRule,
    ProgramScope,
    ScopeTarget,
    Severity,
    Technique,
    Verdict,
    compute_fingerprint,
)
from .scope import ScopeImporter, host_matches, resolve_scope, target_matches_pattern
from .authority import Approval, AuthorizationGate, StopConditionEngine, StopConditions
from .evidence import EvidenceVault, Redactor, redact
from .triage import CVSSv31, TriageScorer, score_vector
from .report import ReportGenerator
from .dedupe import DedupRegistry, DedupVerdict
from .runner import (
    AgathonAdapter,
    CaseRunner,
    EngineResult,
    FindingBuilder,
    TechniqueRegistry,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # errors
    "BountyModeError",
    "ScopeViolationError",
    "AuthorizationError",
    "StopConditionError",
    "EvidenceError",
    "ReportError",
    # models
    "Severity",
    "Technique",
    "Finding",
    "Observation",
    "ProgramScope",
    "ScopeTarget",
    "OutOfScopeRule",
    "AuthorizationDecision",
    "Verdict",
    "compute_fingerprint",
    # scope
    "ScopeImporter",
    "host_matches",
    "resolve_scope",
    "target_matches_pattern",
    # authority
    "Approval",
    "AuthorizationGate",
    "StopConditionEngine",
    "StopConditions",
    # evidence
    "EvidenceVault",
    "Redactor",
    "redact",
    # triage
    "CVSSv31",
    "TriageScorer",
    "score_vector",
    # report
    "ReportGenerator",
    # dedupe
    "DedupRegistry",
    "DedupVerdict",
    # runner
    "AgathonAdapter",
    "CaseRunner",
    "EngineResult",
    "FindingBuilder",
    "TechniqueRegistry",
]
