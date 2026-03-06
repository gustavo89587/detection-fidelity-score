# dfs_core/audit_ledger.py
"""
DFS Audit Ledger — Append-Only Hash-Chained Log

Every agent decision, guardrail evaluation, circuit breaker event,
and ABAC token operation is recorded in an immutable ledger.

Each entry contains:
  - The full event payload
  - Timestamp
  - SHA-256 hash of the entry content
  - SHA-256 hash of the PREVIOUS entry (chain link)
  - Entry index

This creates a hash chain: tampering with any entry breaks all
subsequent hashes — making manipulation detectable.

Not a blockchain (no consensus, no distributed nodes) but provides:
  ✓ Append-only (no delete, no modify)
  ✓ Tamper-evident (hash chain)
  ✓ Forensically auditable (full event payload)
  ✓ Exportable (JSON, JSONL, CSV)

Chris Hughes: "Logs... written to an immutable structure.
If something goes wrong, there is a forensic trail
that is impossible to erase."
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger("dfs.audit_ledger")


# ---------------------------------------------------------------------------
# Ledger Entry
# ---------------------------------------------------------------------------

@dataclass
class LedgerEntry:
    index:          int
    event_type:     str      # GUARDRAIL | CIRCUIT_BREAKER | ABAC | AGENT_ACTION | CUSTOM
    agent_id:       Optional[str]
    action_type:    Optional[str]
    dfs_score:      Optional[float]
    decision:       Optional[str]   # AUTOMATE | ESCALATE | TRIAGE | BLOCK | TRIP | etc.
    payload:        Dict[str, Any]  # full event data
    timestamp:      str
    unix_time:      float
    entry_hash:     str = ""        # SHA-256 of this entry (computed after creation)
    prev_hash:      str = ""        # SHA-256 of previous entry (chain link)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    def compute_hash(self) -> str:
        """Compute SHA-256 of this entry's content (excluding entry_hash field)."""
        content = json.dumps({
            k: v for k, v in self.to_dict().items()
            if k != "entry_hash"
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def verify(self) -> bool:
        """Check that entry_hash matches content."""
        return self.entry_hash == self.compute_hash()


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class DFSAuditLedger:
    """
    Append-only hash-chained audit ledger.

    Usage:
        ledger = DFSAuditLedger()

        # Record any event
        ledger.append(
            event_type="GUARDRAIL",
            agent_id="agent-01",
            action_type="deploy_to_production",
            dfs_score=0.5743,
            decision="ESCALATE",
            payload=decision.to_dict(),
        )

        # Verify integrity
        result = ledger.verify_chain()
        print(result.valid, result.broken_at_index)

        # Export for forensics
        ledger.export_jsonl("audit_2026.jsonl")
    """

    GENESIS_HASH = "0" * 64   # genesis block — no previous entry

    def __init__(
        self,
        persist_path: Optional[str] = None,
        auto_flush: bool = True,
    ):
        self._entries: List[LedgerEntry] = []
        self._persist_path = persist_path
        self._auto_flush = auto_flush

        # Load existing ledger if path given
        if persist_path and Path(persist_path).exists():
            self._load(persist_path)

    def append(
        self,
        event_type:     str,
        payload:        Dict[str, Any],
        agent_id:       Optional[str] = None,
        action_type:    Optional[str] = None,
        dfs_score:      Optional[float] = None,
        decision:       Optional[str] = None,
    ) -> LedgerEntry:
        """Append an immutable entry to the ledger."""
        now = time.time()
        prev_hash = (
            self._entries[-1].entry_hash
            if self._entries
            else self.GENESIS_HASH
        )

        entry = LedgerEntry(
            index       = len(self._entries),
            event_type  = event_type,
            agent_id    = agent_id,
            action_type = action_type,
            dfs_score   = dfs_score,
            decision    = decision,
            payload     = payload,
            timestamp   = datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            unix_time   = now,
            prev_hash   = prev_hash,
        )
        entry.entry_hash = entry.compute_hash()

        self._entries.append(entry)

        if self._auto_flush and self._persist_path:
            self._flush_last(entry)

        return entry

    def verify_chain(self) -> "VerificationResult":
        """
        Verify the integrity of the entire ledger.
        Returns the index of the first broken entry, or None if intact.
        """
        if not self._entries:
            return VerificationResult(valid=True, total=0)

        # Check genesis
        if self._entries[0].prev_hash != self.GENESIS_HASH:
            return VerificationResult(
                valid=False, broken_at_index=0,
                reason="Genesis entry has wrong prev_hash",
                total=len(self._entries),
            )

        for i, entry in enumerate(self._entries):
            # Verify own hash
            if not entry.verify():
                return VerificationResult(
                    valid=False, broken_at_index=i,
                    reason=f"Entry {i} hash mismatch — content was modified",
                    total=len(self._entries),
                )

            # Verify chain link
            if i > 0:
                expected_prev = self._entries[i - 1].entry_hash
                if entry.prev_hash != expected_prev:
                    return VerificationResult(
                        valid=False, broken_at_index=i,
                        reason=f"Entry {i} chain broken — prev_hash mismatch",
                        total=len(self._entries),
                    )

        return VerificationResult(
            valid=True,
            total=len(self._entries),
            reason=f"Chain intact — {len(self._entries)} entries verified",
        )

    def query(
        self,
        agent_id:    Optional[str] = None,
        event_type:  Optional[str] = None,
        decision:    Optional[str] = None,
        since_unix:  Optional[float] = None,
        limit:       int = 100,
    ) -> List[LedgerEntry]:
        """Query ledger entries with filters."""
        results = self._entries
        if agent_id:
            results = [e for e in results if e.agent_id == agent_id]
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        if decision:
            results = [e for e in results if e.decision == decision]
        if since_unix:
            results = [e for e in results if e.unix_time >= since_unix]
        return results[-limit:]

    def stats(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Summary statistics for the ledger or a specific agent."""
        entries = self._entries
        if agent_id:
            entries = [e for e in entries if e.agent_id == agent_id]

        decisions = [e.decision for e in entries if e.decision]
        scores = [e.dfs_score for e in entries if e.dfs_score is not None]

        return {
            "total_entries":    len(entries),
            "automate":         decisions.count("AUTOMATE"),
            "escalate":         decisions.count("ESCALATE"),
            "triage":           decisions.count("TRIAGE"),
            "block":            decisions.count("BLOCK"),
            "trips":            decisions.count("TRIP"),
            "avg_dfs_score":    round(sum(scores) / len(scores), 4) if scores else None,
            "min_dfs_score":    round(min(scores), 4) if scores else None,
            "max_dfs_score":    round(max(scores), 4) if scores else None,
            "chain_valid":      self.verify_chain().valid,
        }

    def export_jsonl(self, path: str) -> int:
        """Export ledger as JSONL (one JSON object per line)."""
        with open(path, "w", encoding="utf-8") as f:
            for entry in self._entries:
                f.write(entry.to_json() + "\n")
        return len(self._entries)

    def export_json(self, path: str) -> int:
        """Export ledger as JSON array."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump([e.to_dict() for e in self._entries], f, indent=2)
        return len(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[LedgerEntry]:
        return iter(self._entries)

    def _flush_last(self, entry: LedgerEntry) -> None:
        """Append last entry to persist file (JSONL)."""
        with open(self._persist_path, "a", encoding="utf-8") as f:
            f.write(entry.to_json() + "\n")

    def _load(self, path: str) -> None:
        """Load existing JSONL ledger from disk."""
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    entry = LedgerEntry(**d)
                    self._entries.append(entry)
                except Exception as e:
                    logger.error(f"Failed to load ledger entry: {e}")


@dataclass
class VerificationResult:
    valid:              bool
    total:              int = 0
    broken_at_index:    Optional[int] = None
    reason:             str = ""


# Singleton
default_ledger = DFSAuditLedger()
