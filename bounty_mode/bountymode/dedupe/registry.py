"""De-duplication and regression-retest registry.

Two jobs, both about not wasting a triager's time:

* **De-duplication** — never submit the same issue twice.  Findings are
  bucketed by a stable :func:`~bountymode.models.compute_fingerprint` over
  ``(category, target, technique, title)``, and a new finding that matches a
  known one is marked ``duplicate`` instead of ``new``.  A program can export
  its already-known issues and they are imported the same way.
* **Regression retest** — after a fix, re-run the finding and record whether
  it still reproduces, so the report can be closed or escalated with evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Finding, compute_fingerprint


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DedupVerdict(str, Enum):
    NEW = "new"
    DUPLICATE = "duplicate"
    RETEST = "retest"


@dataclass
class RegistryEntry:
    fingerprint: str
    finding_id: str
    title: str
    target: str
    category: str
    status: str = "new"
    first_seen: str = field(default_factory=_now_iso)
    last_seen: str = field(default_factory=_now_iso)
    times_seen: int = 1
    retests: List[Dict[str, Any]] = field(default_factory=list)
    known_issue: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "finding_id": self.finding_id,
            "title": self.title,
            "target": self.target,
            "category": self.category,
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "times_seen": self.times_seen,
            "retests": self.retests,
            "known_issue": self.known_issue,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RegistryEntry":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class DedupRegistry:
    """Persistent, file-backed registry of everything already found."""

    def __init__(self, path: str = "registry.json") -> None:
        self.path = Path(path)
        self.entries: Dict[str, RegistryEntry] = {}
        if self.path.exists():
            self._load()

    # -- core -------------------------------------------------------------- #

    def check(self, finding: Finding) -> DedupVerdict:
        """Classify a finding without recording it."""
        fp = finding.fingerprint or compute_fingerprint(
            finding.category, finding.target, finding.technique_id, finding.title
        )
        entry = self.entries.get(fp)
        if entry is None:
            return DedupVerdict.NEW
        return DedupVerdict.DUPLICATE

    def register(self, finding: Finding, *, known_issue: bool = False) -> DedupVerdict:
        """Record a finding and return its de-duplication verdict."""
        fp = finding.fingerprint or compute_fingerprint(
            finding.category, finding.target, finding.technique_id, finding.title
        )
        finding.fingerprint = fp
        existing = self.entries.get(fp)

        if existing is None:
            self.entries[fp] = RegistryEntry(
                fingerprint=fp,
                finding_id=finding.id,
                title=finding.title,
                target=finding.target,
                category=finding.category,
                status="new" if not known_issue else "duplicated",
                known_issue=known_issue,
            )
            finding.status = "new" if not known_issue else "duplicated"
            self._save()
            return DedupVerdict.NEW

        existing.times_seen += 1
        existing.last_seen = _now_iso()
        finding.status = "duplicated"
        self._save()
        return DedupVerdict.DUPLICATE

    # -- known issues / retest --------------------------------------------- #

    def import_known_issues(self, issues: List[Dict[str, Any]]) -> int:
        """Seed the registry from a program's published known-issue list.

        Each item is a mapping with at least ``title`` and optionally
        ``category`` / ``target`` / ``technique_id``.  Returns the number
        imported.
        """
        n = 0
        for issue in issues:
            fp = compute_fingerprint(
                issue.get("category", ""),
                issue.get("target", ""),
                issue.get("technique_id", ""),
                issue.get("title", ""),
            )
            if fp in self.entries:
                self.entries[fp].known_issue = True
                continue
            self.entries[fp] = RegistryEntry(
                fingerprint=fp,
                finding_id=issue.get("id", f"known-{fp}"),
                title=issue.get("title", ""),
                target=issue.get("target", ""),
                category=issue.get("category", ""),
                status="duplicated",
                known_issue=True,
            )
            n += 1
        self._save()
        return n

    def mark_retest(
        self, finding_id: str, *, still_reproduces: bool, note: str = ""
    ) -> Optional[RegistryEntry]:
        """Record a regression retest for a previously-reported finding."""
        for entry in self.entries.values():
            if entry.finding_id == finding_id:
                entry.retests.append(
                    {
                        "at": _now_iso(),
                        "still_reproduces": bool(still_reproduces),
                        "note": note,
                    }
                )
                entry.status = "fixed" if not still_reproduces else "retested"
                entry.last_seen = _now_iso()
                self._save()
                return entry
        return None

    def get(self, finding_id: str) -> Optional[RegistryEntry]:
        for entry in self.entries.values():
            if entry.finding_id == finding_id:
                return entry
        return None

    # -- reporting --------------------------------------------------------- #

    def summary(self) -> Dict[str, int]:
        out = {"total": len(self.entries), "known_issue": 0, "retested": 0, "fixed": 0}
        for e in self.entries.values():
            if e.known_issue:
                out["known_issue"] += 1
            if e.status == "retested":
                out["retested"] += 1
            if e.status == "fixed":
                out["fixed"] += 1
        return out

    # -- persistence ------------------------------------------------------- #

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        for raw in data.get("entries", []):
            entry = RegistryEntry.from_dict(raw)
            self.entries[entry.fingerprint] = entry

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": _now_iso(),
            "summary": self.summary(),
            "entries": [e.to_dict() for e in self.entries.values()],
        }
        self.path.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
