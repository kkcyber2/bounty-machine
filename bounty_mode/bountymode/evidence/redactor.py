"""Redaction engine.

Bug-bounty evidence must prove impact **without** exfiltrating the very data
the bug is about.  This module rewrites secrets, credentials and personal data
in captured evidence into labelled placeholders (``[REDACTED:openai_key]``)
while leaving a machine-checkable audit trail of what was removed.

Design goals:

* **High recall on credentials.**  Missing a live API key in a screenshot of
  evidence is a real harm; over-redacting a long random string is only a minor
  inconvenience.
* **Deterministic.**  The same input always yields the same output, so the
  vault's content hash is meaningful.
* **Explainable.**  Every substitution reports its category and offset.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Pattern, Tuple


@dataclass
class Redaction:
    category: str
    start: int
    end: int
    preview: str  # safe, non-reversible hint (never the secret itself)


@dataclass
class RedactionResult:
    text: str
    redactions: List[Redaction] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.redactions)

    def by_category(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in self.redactions:
            out[r.category] = out.get(r.category, 0) + 1
        return out


# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

#: Ordered so that more specific patterns win before generic ones.
_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    # --- secrets / credentials -------------------------------------------- #
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", re.S)),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b")),
    ("groq_key", re.compile(r"\bgsk_[A-Za-z0-9]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}\b")),
    ("bearer_token", re.compile(r"(?i)\b(?:authorization|bearer)\b\s*[:=]?\s*(?:bearer\s+)?([A-Za-z0-9._\-]{20,})")),
    ("password_field", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b[\"']?\s*[:=]\s*[\"']?(?!\[REDACTED:)([^\s\"',;}]{6,})")),
    ("connection_string", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"'<>]+")),

    # --- personal data ----------------------------------------------------- #
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("phone", re.compile(r"(?<![\w.])(?:\+\d{1,3}[ \-.]?)?(?:\(\d{2,4}\)[ \-.]?)?\d{3,4}[ \-.]\d{3,4}(?:[ \-.]\d{2,4})?(?![\w.])")),

    # --- infrastructure ---------------------------------------------------- #
    ("private_ip", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")),
]

#: Sensible defaults when a caller does not pick categories.
DEFAULT_CATEGORIES = {
    "private_key", "openai_key", "anthropic_key", "groq_key", "google_api_key",
    "aws_access_key", "github_token", "slack_token", "jwt", "bearer_token",
    "password_field", "connection_string", "email", "credit_card", "ssn",
}


class Redactor:
    """Apply deterministic, categorised redaction to text."""

    def __init__(self, categories: Dict[str, bool] | None = None, placeholder_style: str = "label") -> None:
        self.categories: Dict[str, bool] = {}
        names = [name for name, _ in _PATTERNS] + ["phone", "private_ip"]
        for n in names:
            self.categories[n] = n in DEFAULT_CATEGORIES
        # personal-data categories default off unless asked for
        self.categories["phone"] = False
        self.categories["private_ip"] = False
        if categories:
            self.categories.update(categories)
        self.placeholder_style = placeholder_style

    def _placeholder(self, category: str) -> str:
        if self.placeholder_style == "label":
            return f"[REDACTED:{category}]"
        return "[REDACTED]"

    def redact(self, text: str) -> RedactionResult:
        """Return a :class:`RedactionResult` for ``text``."""
        if not text:
            return RedactionResult(text=text or "")

        work = text
        found: List[Redaction] = []
        # Iterate patterns; re-scan after each replacement so offsets stay valid
        # for the *final* string.
        for category, pattern in _PATTERNS:
            if not self.categories.get(category):
                continue
            if not pattern.search(work):
                continue

            def _sub(match: re.Match, cat: str = category) -> str:
                hit = match.group(0)
                found.append(
                    Redaction(
                        category=cat,
                        start=match.start(),
                        end=match.end(),
                        preview=_safe_preview(hit),
                    )
                )
                return self._placeholder(cat)

            work = pattern.sub(_sub, work)

        # Offsets were captured against intermediate strings; recompute final
        # offsets so the audit trail is accurate.
        for r in found:
            r.start = work.find(self._placeholder(r.category))
            r.end = r.start + len(self._placeholder(r.category)) if r.start >= 0 else -1

        return RedactionResult(text=work, redactions=found)


def _safe_preview(value: str) -> str:
    """A non-reversible hint: length + first char class only."""
    v = value.strip()
    return f"len={len(v)}"


def redact(text: str, categories: Dict[str, bool] | None = None) -> str:
    """Convenience one-shot redaction."""
    return Redactor(categories).redact(text).text
