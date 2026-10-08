"""Engine adapter — bridges Bounty Mode to the Agathon red-teaming engine.

Bounty Mode does **not** implement attacks.  It drives them.  This module is
the seam:

* :class:`TechniqueRegistry` — the catalogue of test-case steps, mapped onto
  the engine's ``attacks/`` modules and dynamic plugins.
* :class:`EngineResult` — a stable, engine-agnostic result record mirroring the
  engine's ``attacks/base_tester.py::AttackResult`` fields.
* :class:`AgathonAdapter` — an HTTP client for the engine's scan surface
  (``POST /scan/start``), which normalises the response.
* :class:`FindingBuilder` — turns a successful :class:`EngineResult` into a
  :class:`~bountymode.models.Finding` with the fields a triager needs.

The adapter performs **only** the call it is given.  Scope enforcement happens
one layer up, in the gate, before a dispatcher is ever reached.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models import Finding, Technique


# --------------------------------------------------------------------------- #
# Technique catalogue
# --------------------------------------------------------------------------- #

def _t(id: str, name: str, engine_key: str, category: str, **kw: Any) -> Technique:
    return Technique(id=id, name=name, engine_key=engine_key, category=category, **kw)


#: The test-case catalogue.  Keys map to engine attack modules
#: (``attacks/*.py`` class names) or dynamic plugin ids discovered at runtime.
DEFAULT_TECHNIQUES: List[Technique] = [
    _t("prompt_injection", "Direct prompt injection", "PromptInjectionTester",
       "prompt_injection", severity_hint="high",
       description="Attempt to override system instructions with a direct instruction."),
    _t("indirect_injection", "Indirect prompt injection", "IndirectInjectionTester",
       "indirect_injection", severity_hint="high",
       description="Inject instructions via retrieved content the model later consumes.",
       tags=["rag", "agentic"]),
    _t("system_prompt_leak", "System prompt extraction", "SystemPromptExtractor",
       "system_prompt_leak", severity_hint="low",
       description="Try to disclose the model's hidden system instructions."),
    _t("data_exfiltration", "Sensitive data exfiltration", "DataExfiltrationTester",
       "data_exfiltration", severity_hint="high",
       description="Attempt to pull secrets or PII the model was given."),
    _t("rag_poisoning", "RAG poisoning / cross-document", "RAGPoisoningTester",
       "rag_poisoning", severity_hint="high", tags=["rag"]),
    _t("cross_tenant", "Cross-tenant data isolation", "CrossTenantTester",
       "cross_tenant", severity_hint="critical", requires_auth=True,
       description="Check whether one tenant can read another tenant's data.", tags=["agentic"]),
    _t("excessive_agency", "Excessive agency / unauthorized tool use", "ExcessiveAgencyTester",
       "excessive_agency", severity_hint="high", side_effects=True, requires_auth=True,
       tags=["agentic"]),
    _t("tool_misuse", "Tool / function-call misuse", "ToolMisuseTester",
       "tool_misuse", severity_hint="high", side_effects=True, requires_auth=True,
       tags=["agentic"]),
    _t("access_control", "Access control around AI features", "AccessControlTester",
       "access_control", severity_hint="high", requires_auth=True),
    _t("output_handling", "Unsafe output handling", "OutputHandlingTester",
       "output_handling", severity_hint="high",
       description="Model output consumed unsafely downstream (XSS / SSRF / code exec)."),
    _t("context_manipulation", "Context manipulation", "ContextManipulationTester",
       "context_manipulation", severity_hint="medium"),
    _t("jailbreak", "Jailbreak / guardrail bypass", "GuardrailBypassTester",
       "jailbreak", severity_hint="low",
       description="Policy bypass with no demonstrated data or action impact."),
    _t("multimodal_injection", "Multimodal image/audio injection", "MultimodalInjectionTester",
       "multimodal_injection", severity_hint="high", requires_multimodal=True),
    _t("supply_chain", "Model / dependency supply chain", "SupplyChainTester",
       "supply_chain", severity_hint="high"),
    # Disruptive — blocked by the gate for every program.
    _t("economic_denial", "Denial of service / economic exhaustion", "EconomicDenialTester",
       "economic_denial", severity_hint="medium", destructive=True,
       description="Blocked by default: prohibited by virtually every program."),
]


class TechniqueRegistry:
    """Look up test-case steps by id or engine key."""

    def __init__(self, techniques: Optional[List[Technique]] = None) -> None:
        self._by_id: Dict[str, Technique] = {}
        self._by_engine_key: Dict[str, Technique] = {}
        for t in techniques or DEFAULT_TECHNIQUES:
            self._by_id[t.id] = t
            if t.engine_key:
                self._by_engine_key[t.engine_key] = t

    def all(self) -> List[Technique]:
        return list(self._by_id.values())

    def ids(self) -> List[str]:
        return list(self._by_id.keys())

    def get(self, key: str) -> Optional[Technique]:
        if key in self._by_id:
            return self._by_id[key]
        return self._by_engine_key.get(key)

    def require(self, key: str) -> Technique:
        t = self.get(key)
        if t is None:
            raise KeyError(f"unknown technique: {key!r} (known: {', '.join(self.ids())})")
        return t

    def resolve_many(self, keys: List[str]) -> List[Technique]:
        return [self.require(k) for k in keys]


# --------------------------------------------------------------------------- #
# Engine result
# --------------------------------------------------------------------------- #

@dataclass
class EngineResult:
    """Normalised result of one engine test.

    Mirrors the engine's ``attacks/base_tester.py::AttackResult`` so an adapter
    can map fields 1:1 without guessing.
    """

    technique_id: str
    target: str
    success: bool = False
    success_score: float = 0.0
    payload_used: str = ""
    response: str = ""
    evidence: str = ""
    vulnerability_type: str = ""
    target_model: str = ""
    tokens_used: int = 0
    duration_ms: float = 0.0
    error: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], technique_id: str, target: str) -> "EngineResult":
        """Best-effort mapping from a heterogeneous engine response."""
        g = raw.get
        return cls(
            technique_id=technique_id,
            target=target,
            success=bool(g("success", g("is_successful", g("found", False)))),
            success_score=float(g("success_score", g("score", g("confidence", 0.0))) or 0.0),
            payload_used=g("payload_used", g("payload", g("prompt", ""))) or "",
            response=g("response", g("model_response", g("output", ""))) or "",
            evidence=g("evidence", g("details", g("reason", ""))) or "",
            vulnerability_type=g("vulnerability_type", g("vuln_type", "")) or "",
            target_model=g("target_model", g("model", "")) or "",
            tokens_used=int(g("tokens_used", g("tokens", 0)) or 0),
            duration_ms=float(g("duration_ms", g("latency_ms", 0.0)) or 0.0),
            error=g("error", "") or "",
            metadata=raw,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "target": self.target,
            "success": self.success,
            "success_score": self.success_score,
            "vulnerability_type": self.vulnerability_type,
            "target_model": self.target_model,
            "tokens_used": self.tokens_used,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


# --------------------------------------------------------------------------- #
# Finding builder
# --------------------------------------------------------------------------- #

#: How each technique maps onto a CVSS-ish starting category.
_CATEGORY_DEFAULTS = {
    "prompt_injection": ("high", ["CWE-1426"], ["LLM01"]),
    "indirect_injection": ("high", ["CWE-1426"], ["LLM01", "LLM05"]),
    "system_prompt_leak": ("low", ["CWE-200"], ["LLM06"]),
    "data_exfiltration": ("high", ["CWE-200"], ["LLM02"]),
    "rag_poisoning": ("high", ["CWE-1426"], ["LLM01", "LLM04"]),
    "cross_tenant": ("critical", ["CWE-639", "CWE-284"], ["LLM02", "LLM06"]),
    "excessive_agency": ("high", ["CWE-269"], ["LLM08"]),
    "tool_misuse": ("high", ["CWE-269"], ["LLM07"]),
    "access_control": ("high", ["CWE-284"], ["LLM02"]),
    "output_handling": ("high", ["CWE-79"], ["LLM05"]),
    "context_manipulation": ("medium", ["CWE-1426"], ["LLM01"]),
    "jailbreak": ("low", ["CWE-693"], ["LLM01"]),
    "multimodal_injection": ("high", ["CWE-1426"], ["LLM01"]),
    "supply_chain": ("high", ["CWE-1104"], ["LLM05"]),
    "economic_denial": ("medium", ["CWE-770"], ["LLM10"]),
}

_TITLES = {
    "prompt_injection": "Direct prompt injection bypasses the assistant's guardrails",
    "indirect_injection": "Indirect prompt injection via retrieved content",
    "system_prompt_leak": "System prompt disclosed to an unprivileged user",
    "data_exfiltration": "Sensitive data extracted from the model context",
    "rag_poisoning": "Retrieval corpus can be poisoned to steer answers",
    "cross_tenant": "Cross-tenant data disclosure through the assistant",
    "excessive_agency": "Assistant performs unauthorized actions via its tools",
    "tool_misuse": "Assistant tool call can be redirected to an unintended operation",
    "access_control": "Missing access control on an AI-facing endpoint",
    "output_handling": "Unsafe handling of model output enables downstream injection",
    "context_manipulation": "Conversation context can be manipulated to alter behaviour",
    "jailbreak": "Guardrail bypass (policy-only, no data impact)",
    "multimodal_injection": "Injection delivered through an image/audio input",
    "supply_chain": "Model or dependency supply-chain weakness",
    "economic_denial": "Resource exhaustion of the assistant endpoint",
}


class FindingBuilder:
    """Turn an engine result into a reportable finding."""

    def build(self, result: EngineResult, technique: Technique) -> Finding:
        severity_hint, cwe, owasp = _CATEGORY_DEFAULTS.get(
            technique.category, ("medium", [], [])
        )
        # A success score carries confidence; a weak hit should not be
        # presented as a strong finding.
        confidence = max(0.0, min(1.0, result.success_score or 0.5))
        reproducible = bool(result.success) and confidence >= 0.6

        return Finding(
            id=_finding_id(technique.id, result.target),
            title=_TITLES.get(technique.category, f"{technique.name} observed on the target"),
            technique_id=technique.id,
            target=result.target,
            category=technique.category,
            confidence=confidence,
            reproducible=reproducible,
            reproduction_rate=1.0 if reproducible else 0.0,
            privileges_required="low" if technique.requires_auth else "none",
            blast_radius="cross-tenant" if technique.category == "cross_tenant" else "single-user",
            description=(
                technique.description
                or f"The '{technique.name}' test produced a positive result against {result.target}."
            ),
            impact=result.evidence or "",
            expected="The target should refuse the request and not disclose data or take the action.",
            actual=result.response[:2000] if result.response else (result.evidence or ""),
            remediation=self._remediation(technique.category),
            affected_asset=result.target,
            cwe=list(cwe),
            owasp_llm=list(owasp),
        )

    @staticmethod
    def _remediation(category: str) -> str:
        return {
            "prompt_injection": "Treat all model input as untrusted; add an input classifier and "
                                "never let model output directly drive privileged actions.",
            "indirect_injection": "Sanitise retrieved content and isolate it from the instruction "
                                  "channel; mark retrieved text as data, not instructions.",
            "system_prompt_leak": "Do not rely on prompt secrecy for security; add an output filter "
                                  "for system-prompt content.",
            "data_exfiltration": "Apply least-privilege data scoping to the model context and add "
                                 "output DLP for secrets and PII.",
            "rag_poisoning": "Validate and provenance-tag retrieved chunks; re-embed only trusted "
                             "sources; add retrieval-time integrity checks.",
            "cross_tenant": "Scope every lookup by the authenticated tenant and add a regression test "
                            "asserting cross-tenant IDs are refused.",
            "excessive_agency": "Require explicit confirmation for side-effecting tools and enforce "
                                "per-tool authorization server-side.",
            "tool_misuse": "Validate tool arguments server-side and use an allow-list of operations.",
            "access_control": "Enforce authorization on the server for every AI-facing endpoint.",
            "output_handling": "Encode model output for its destination context; never eval it.",
            "context_manipulation": "Keep trusted instructions out of the mutable context window.",
            "jailbreak": "Add defence-in-depth: layered filters rather than a single refusal prompt.",
            "multimodal_injection": "Scan image/audio inputs for embedded instructions before the model "
                                    "consumes them.",
            "supply_chain": "Pin model and dependency versions; verify signatures and SBOMs.",
            "economic_denial": "Add per-user rate limits and cost caps. (Do not test this class.)",
        }.get(category, "Apply defence-in-depth at the input, model and output layers.")


def _finding_id(technique_id: str, target: str) -> str:
    import hashlib

    digest = hashlib.sha256(f"{technique_id}|{target}".encode()).hexdigest()[:10]
    return f"F-{digest}"


# --------------------------------------------------------------------------- #
# Engine adapter
# --------------------------------------------------------------------------- #

class AgathonAdapter:
    """HTTP client for the Agathon engine's scan surface.

    Only the two endpoints the engine documents are used:

    ``POST {base}/scan/start``   start one test
    ``GET  {base}/scan/{id}``    poll for the result

    The adapter never decides *whether* to call — that is the gate's job.
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str = "",
        timeout: float = 120.0,
        poll_interval: float = 2.0,
        max_polls: int = 60,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.max_polls = max_polls

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=self._headers(), method="POST"
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")

    def run_test(self, technique: Technique, target: str, **params: Any) -> EngineResult:
        """Start one test and return a normalised result."""
        body = {
            "target": target,
            "attack_type": technique.engine_key or technique.id,
            "technique": technique.id,
            "params": {**technique.params, **params},
        }
        try:
            raw = self._post("/scan/start", body)
        except urllib.error.HTTPError as exc:
            return EngineResult(
                technique_id=technique.id, target=target, success=False,
                error=f"HTTP {exc.code}: {exc.reason}",
            )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return EngineResult(
                technique_id=technique.id, target=target, success=False,
                error=f"connection error: {exc}",
            )
        except json.JSONDecodeError as exc:
            return EngineResult(
                technique_id=technique.id, target=target, success=False,
                error=f"invalid engine response: {exc}",
            )

        # Some engine builds return the result inline; support both shapes.
        if isinstance(raw, dict) and ("success" in raw or "result" in raw):
            payload = raw.get("result", raw)
            return EngineResult.from_dict(payload, technique.id, target)

        scan_id = (raw or {}).get("scan_id") or (raw or {}).get("id")
        if not scan_id:
            return EngineResult.from_dict(raw or {}, technique.id, target)
        return self._poll(scan_id, technique, target)

    def _poll(self, scan_id: str, technique: Technique, target: str) -> EngineResult:
        import time

        for _ in range(self.max_polls):
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/scan/{scan_id}", headers=self._headers()
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = json.loads(resp.read().decode("utf-8") or "{}")
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                return EngineResult(
                    technique_id=technique.id, target=target, success=False,
                    error=f"poll error: {exc}",
                )
            state = (raw or {}).get("status", "complete")
            if state in ("complete", "completed", "done", "finished", "failed", "error"):
                payload = raw.get("result", raw) if state != "failed" else {
                    "success": False, "error": raw.get("error", "engine reported failure")
                }
                return EngineResult.from_dict(payload, technique.id, target)
            time.sleep(self.poll_interval)

        return EngineResult(
            technique_id=technique.id, target=target, success=False,
            error=f"scan {scan_id} did not complete within {self.max_polls} polls",
        )
