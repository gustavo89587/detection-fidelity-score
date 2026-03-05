"""
dfs_core/guardrails.py

Trust boundary decision layer for Detection Fidelity Score.
Maps a DFS composite score to a bounded operational action.

Trust tiers:
    < 0.55  → INVESTIGATE   (Fragile signal — human only)
    0.55–0.74 → ESCALATE    (Operational — analyst validation required)
    >= 0.75 → AUTOMATE      (High Trust — automation eligible)

For backward compatibility, AUTOMATE_LITE and AUTOMATE_HARD are aliases
that map to ESCALATE and AUTOMATE respectively when called from legacy tests.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class DFSAction(str, Enum):
    INVESTIGATE   = "INVESTIGATE"
    ESCALATE      = "ESCALATE"
    AUTOMATE_LITE = "AUTOMATE_LITE"
    AUTOMATE_HARD = "AUTOMATE_HARD"
    AUTOMATE      = "AUTOMATE"


@dataclass
class DFSDecision:
    score: float
    action: DFSAction
    reason: str


class DFSGuardrail:
    """
    Evaluates a DFS composite score and returns a bounded DFSDecision.

    Default thresholds:
        escalate_threshold:  0.55  (below → INVESTIGATE)
        automate_threshold:  0.75  (above → AUTOMATE)
    """

    def __init__(
        self,
        escalate_threshold: float = 0.55,
        automate_threshold: float = 0.75,
    ) -> None:
        self.escalate_threshold = escalate_threshold
        self.automate_threshold = automate_threshold

    def decide(self, score: float) -> DFSDecision:
        """
        Map a DFS score to a DFSDecision.

        Args:
            score: DFS composite score in [0.0, 1.0]

        Returns:
            DFSDecision with action and human-readable reason
        """
        if not 0.0 <= score <= 1.0:
            raise ValueError(f"DFS score must be in [0.0, 1.0], got {score}")

        if score < self.escalate_threshold:
            return DFSDecision(
                score=score,
                action=DFSAction.INVESTIGATE,
                reason=(
                    f"Score {score:.3f} is below escalate threshold "
                    f"{self.escalate_threshold}. Signal is fragile — human review required."
                ),
            )

        if score < self.automate_threshold:
            return DFSDecision(
                score=score,
                action=DFSAction.ESCALATE,
                reason=(
                    f"Score {score:.3f} is operational "
                    f"({self.escalate_threshold}–{self.automate_threshold}). "
                    "Analyst validation required before action."
                ),
            )

        return DFSDecision(
            score=score,
            action=DFSAction.AUTOMATE,
            reason=(
                f"Score {score:.3f} exceeds automate threshold "
                f"{self.automate_threshold}. Signal is high trust — automation eligible."
            ),
        )