"""Program-scope importer.

Turns a bug-bounty program policy into a :class:`ProgramScope`.

Three input shapes are supported, in order of reliability:

1. **JSON** (``.json``) — the canonical, lossless format.  Feed this the output
   of ``ScopeImporter.export()`` or hand-write it.
2. **YAML** (``.yaml`` / ``.yml``) — convenience format for humans.  Requires
   ``PyYAML``; if it is missing the importer fails with a clear message rather
   than guessing.
3. **Markdown / plain text** (``.md`` / ``.txt``) — a best-effort parser for a
   policy you copy-pasted from HackerOne / Bugcrowd / Intigriti / YesWeHack.

The text parser is deliberately conservative and *always* records what it did
in :attr:`ProgramScope.source_url` / a ``warnings`` list returned alongside the
scope, so a human can review before anything is authorized.  It is a starting
point, never a substitute for reading the policy.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import OutOfScopeRule, ProgramScope, ScopeTarget

# --------------------------------------------------------------------------- #
# Keyword maps
# --------------------------------------------------------------------------- #

#: Policy phrases that map onto a technique id we can forbid.
_PROHIBITED_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\b(?:denial[- ]of[- ]service|dos|ddos)\b", re.I), "economic_denial"),
    (re.compile(r"\brate[- ]limit", re.I), "economic_denial"),
    (re.compile(r"\bsocial engineer", re.I), "social_bot_auditor"),
    (re.compile(r"\bphishing\b", re.I), "social_bot_auditor"),
    (re.compile(r"\bphysical(?: security)?\b", re.I), "physical"),
    (re.compile(r"\bmalware\b", re.I), "malware"),
    (re.compile(r"\bauto(?:mated)? scanners?\b", re.I), "automated_scanner"),
]

_PLATFORM_HINTS = {
    "hackerone": "hackerone",
    "bugcrowd": "bugcrowd",
    "intigriti": "intigriti",
    "yeswehack": "yeswehack",
    "synack": "synack",
}

_HOST_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b", re.I)
_URL_RE = re.compile(r"https?://[^\s)\]\"'`,;]+", re.I)
_RATE_RE = re.compile(
    r"(\d+)\s*(?:req(?:uest)?s?)\s*(?:per|/)\s*(sec(?:ond)?|min(?:ute)?|hour|h|s)\b",
    re.I,
)
_MAX_REQ_RE = re.compile(r"(?:max(?:imum)?|no more than|limit of)\s*(\d{2,6})\s*req", re.I)
_DURATION_RE = re.compile(r"(\d+)\s*(hour|hr|h|minute|min)s?\b", re.I)

_IN_SCOPE_HEAD = re.compile(
    r"(?:^|\n)[#*\-\s]*(?:in[\s-]?scope|scope(?:\s*of\s*work)?|eligible(?:\s*assets)?|targets?)\b.*?:?\s*\n",
    re.I,
)
_OUT_SCOPE_HEAD = re.compile(
    r"(?:^|\n)[#*\-\s]*(?:out[\s-]?of[\s-]?scope|not[\s-]?in[\s-]?scope|exclusions?|non[\s-]?eligible)\b.*?:?\s*\n",
    re.I,
)

#: Hosts that can never be a legitimate bounty target.
_DENY_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "169.254.169.254",
    "metadata.google.internal",
}


class ScopeImporter:
    """Import a program policy into a :class:`ProgramScope`."""

    def __init__(self) -> None:
        self.warnings: List[str] = []

    # -- public API -------------------------------------------------------- #

    def from_dict(self, data: Dict[str, Any], program: Optional[str] = None) -> ProgramScope:
        """Build a scope from an already-parsed mapping."""
        data = dict(data)
        if program:
            data["program"] = program
        self._normalize_keys(data)
        scope = ProgramScope.from_dict(data)
        scope.in_scope = [t for t in scope.in_scope if self._safe_pattern(t.pattern)]
        self._merge_prohibited(scope)
        return scope

    def from_json(self, text: str) -> ProgramScope:
        return self.from_dict(json.loads(text))

    def from_yaml(self, text: str) -> ProgramScope:
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - exercised only w/o pyyaml
            raise RuntimeError(
                "PyYAML is required to import YAML policies. "
                "Install it (`pip install pyyaml`) or use JSON instead."
            ) from exc
        return self.from_dict(yaml.safe_load(text))

    def from_text(self, text: str, program: str = "imported-program") -> ProgramScope:
        """Best-effort parse of a markdown/plain-text policy."""
        self.warnings = []
        platform = self._detect_platform(text)

        in_block = self._section(text, _IN_SCOPE_HEAD, _OUT_SCOPE_HEAD)
        out_block = self._section(text, _OUT_SCOPE_HEAD, _IN_SCOPE_HEAD)

        in_scope = self._extract_targets(in_block or text)
        out_scope = self._extract_targets(out_block or "")

        scope = ProgramScope(
            program=program,
            platform=platform,
            in_scope=[ScopeTarget(pattern=p) for p in in_scope],
            out_of_scope=[OutOfScopeRule(pattern=p, reason="listed as out of scope") for p in out_scope],
            safe_harbour=bool(re.search(r"safe[\s-]?harbou?r", text, re.I)),
        )

        scope.rate_limit_rps, scope.max_requests = self._extract_limits(text)
        dur = _DURATION_RE.search(text)
        if dur:
            n = int(dur.group(1))
            scope.max_duration_s = n * 3600 if dur.group(2).lower().startswith("h") else n * 60

        for pat, tid in _PROHIBITED_PATTERNS:
            if pat.search(text):
                scope.prohibited_techniques.append(tid)

        scope.requires_test_account = bool(re.search(r"test account|research account", text, re.I))
        d = re.search(r"(\d+)[\s-]?day(?:s)?\s*(?:disclosure|embargo)", text, re.I)
        if d:
            scope.disclosure_days = int(d.group(1))

        self._merge_prohibited(scope)

        if not scope.in_scope:
            self.warnings.append(
                "No in-scope assets were found in the policy text. "
                "Add them to the scope JSON before running any test."
            )
        scope.raw_hash = _sha16(text)
        return scope

    def import_file(self, path: str, program: Optional[str] = None) -> ProgramScope:
        """Import a policy from disk, dispatching on extension."""
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        suffix = p.suffix.lower()
        if suffix == ".json":
            scope = self.from_json(text)
        elif suffix in (".yaml", ".yml"):
            scope = self.from_yaml(text)
        else:
            scope = self.from_text(text, program=program or p.stem)

        if not scope.program or scope.program == "generic":
            scope.program = program or p.stem
        if not scope.source_url:
            scope.source_url = f"file://{p.name}"
        if not scope.raw_hash:
            scope.raw_hash = _sha16(text)
        return scope

    def export(self, scope: ProgramScope, path: str) -> None:
        """Write a canonical JSON scope (round-trips losslessly)."""
        Path(path).write_text(
            json.dumps(scope.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
        )

    # -- internals --------------------------------------------------------- #

    def _normalize_keys(self, data: Dict[str, Any]) -> None:
        """Accept camelCase / platform-flavoured keys and normalise them."""
        aliases = {
            "scope": "in_scope",
            "targets": "in_scope",
            "assets": "in_scope",
            "inScope": "in_scope",
            "in-scope": "in_scope",
            "outOfScope": "out_of_scope",
            "out-of-scope": "out_of_scope",
            "excluded": "out_of_scope",
            "forbidden_techniques": "prohibited_techniques",
            "blocked_techniques": "prohibited_techniques",
            "allowed_techniques": "permitted_techniques",
            "name": "program",
            "title": "program",
        }
        for src, dst in aliases.items():
            if src in data and dst not in data:
                data[dst] = data.pop(src)

        entries = data.get("in_scope") or []
        data["in_scope"] = [
            {"pattern": e} if isinstance(e, str) else e for e in entries
        ]
        excl = data.get("out_of_scope") or []
        data["out_of_scope"] = [
            {"pattern": e} if isinstance(e, str) else e for e in excl
        ]

    def _merge_prohibited(self, scope: ProgramScope) -> None:
        """Always-blocked classes, regardless of what the policy says.

        These are disruptive techniques that no reputable program permits via
        automated tooling; they are merged in even if the policy is silent.
        """
        always = {"economic_denial", "destructive", "malware"}
        scope.prohibited_techniques = sorted(
            set(t.lower() for t in scope.prohibited_techniques) | always
        )

    def _detect_platform(self, text: str) -> str:
        low = text.lower()
        for needle, name in _PLATFORM_HINTS.items():
            if needle in low:
                return name
        return "generic"

    def _section(self, text: str, head: re.Pattern, other: re.Pattern) -> str:
        """Return the text between a heading and the next competing heading."""
        m = head.search(text)
        if not m:
            return ""
        start = m.end()
        rest = text[start:]
        nxt = other.search(rest)
        return rest[: nxt.start()] if nxt else rest

    def _extract_targets(self, block: str) -> List[str]:
        found: List[str] = []
        for raw in _URL_RE.findall(block):
            host = re.sub(r"^https?://", "", raw, flags=re.I).split("/")[0].lower()
            if self._safe_pattern(host):
                found.append(host)
        for host in _HOST_RE.findall(block):
            h = host.lower()
            if h.endswith((".md", ".py", ".js", ".json", ".txt")):
                continue
            if self._safe_pattern(h):
                found.append(h)
        # de-dup, preserve order
        seen: Dict[str, None] = {}
        for f in found:
            seen.setdefault(f, None)
        return list(seen)

    def _safe_pattern(self, pattern: str) -> bool:
        if not pattern:
            return False
        p = pattern.strip().lower()
        host = re.sub(r"^https?://", "", p).split("/")[0].split(":")[0]
        if host in _DENY_HOSTS:
            self.warnings.append(f"refused unsafe host in policy: {host}")
            return False
        if host.endswith(".local") or host.endswith(".internal"):
            return False
        return True

    def _extract_limits(self, text: str) -> Tuple[float, int]:
        rps = 1.0
        m = _RATE_RE.search(text)
        if m:
            n = max(1, int(m.group(1)))
            unit = m.group(2).lower()
            if unit.startswith("s"):
                rps = float(n)
            elif unit.startswith("min"):
                rps = n / 60.0
            else:  # hour
                rps = n / 3600.0
            rps = max(rps, 0.01)
        max_req = 500
        m2 = _MAX_REQ_RE.search(text)
        if m2:
            max_req = max(1, int(m2.group(1)))
        return rps, max_req


def _sha16(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
