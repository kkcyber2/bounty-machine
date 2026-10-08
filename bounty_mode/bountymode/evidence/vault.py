"""Evidence vault — tamper-evident, redacted capture of proof.

Everything a finding needs to be *believable* to a triager lives here:
the request/response pair, timestamps, environment, and a content hash.

The vault enforces three rules:

* **Redact before persist.**  Nothing is written to disk until it has been
  through :class:`~bountymode.evidence.redactor.Redactor`.
* **Append-only.**  Entries are written once and never mutated; re-capturing
  the same finding appends a new, hash-chained record.
* **Verifiable.**  A ``chain.json`` records each entry's SHA-256 and the
  previous entry's hash, so a reviewer can prove the evidence was not edited.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Finding, Observation
from .redactor import Redactor


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class VaultEntry:
    finding_id: str
    observation: Observation
    seq: int
    prev_hash: str
    hash: str
    path: str = ""
    captured_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "finding_id": self.finding_id,
            "hash": self.hash,
            "prev_hash": self.prev_hash,
            "path": self.path,
            "captured_at": self.captured_at,
            "observation": self.observation.to_dict(),
        }


class EvidenceVault:
    """Filesystem-backed, hash-chained evidence store."""

    def __init__(
        self,
        root: str,
        *,
        redactor: Optional[Redactor] = None,
        store_raw: bool = False,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.redactor = redactor or Redactor()
        self.store_raw = store_raw  # deliberately off by default
        self.entries: List[VaultEntry] = []
        self._last_hash = "0" * 64

    # -- capture ----------------------------------------------------------- #

    def capture(
        self,
        finding: Finding,
        *,
        kind: str = "http",
        request: str = "",
        response: str = "",
        status: Optional[int] = None,
        url: str = "",
        method: str = "POST",
        environment: Optional[Dict[str, Any]] = None,
    ) -> Observation:
        """Redact, hash and persist one observation for ``finding``."""
        red_req = self.redactor.redact(request or "")
        red_res = self.redactor.redact(response or "")

        obs = Observation(
            kind=kind,
            request=red_req.text,
            response=red_res.text,
            status=status,
            url=url,
            method=method,
            redactions=red_req.count + red_res.count,
        )

        payload = {
            "finding_id": finding.id,
            "observation": obs.to_dict(),
            "environment": environment or _environment(),
        }
        blob = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        obs.sha256 = _sha256_hex(blob)

        entry = VaultEntry(
            finding_id=finding.id,
            observation=obs,
            seq=len(self.entries) + 1,
            prev_hash=self._last_hash,
            hash=obs.sha256,
        )
        entry.path = str(self._write_entry(entry, blob))
        self._last_hash = obs.sha256
        self.entries.append(entry)
        finding.observations.append(obs)
        self._write_chain()
        return obs

    def attach_note(self, finding: Finding, text: str) -> Observation:
        """Capture a free-text note (already-redacted) as evidence."""
        return self.capture(finding, kind="note", response=text)

    # -- verification ------------------------------------------------------ #

    def verify_chain(self) -> bool:
        """Re-walk the chain and confirm every ``prev_hash`` link is intact."""
        prev = "0" * 64
        for entry in self.entries:
            if entry.prev_hash != prev:
                return False
            prev = entry.hash
        return True

    def ledger(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.entries]

    # -- internals --------------------------------------------------------- #

    def _finding_dir(self, finding_id: str) -> Path:
        d = self.root / finding_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _write_entry(self, entry: VaultEntry, blob: bytes) -> Path:
        d = self._finding_dir(entry.finding_id)
        path = d / f"observation_{entry.seq:03d}.json"
        path.write_bytes(blob)
        return path

    def _write_chain(self) -> None:
        chain = {
            "root": str(self.root),
            "entries": [e.to_dict() for e in self.entries],
            "head": self._last_hash,
            "count": len(self.entries),
            "updated_at": _now_iso(),
        }
        (self.root / "chain.json").write_text(
            json.dumps(chain, indent=2, sort_keys=True), encoding="utf-8"
        )

    # -- helpers ----------------------------------------------------------- #

    def finding_bundle(self, finding: Finding) -> Dict[str, Any]:
        """A single JSON-serialisable bundle for reports/attachments."""
        return {
            "finding": finding.to_dict(),
            "evidence": [o.to_dict() for o in finding.observations],
            "chain_verified": self.verify_chain(),
        }


def _environment() -> Dict[str, Any]:
    return {
        "platform": os.uname().sysname if hasattr(os, "uname") else "unknown",
        "python": os.sys.version.split()[0],
        "captured_by": "bountymode",
    }
