# dfs_core/guardrails.py
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class DFSAction(str, Enum):
    INVESTIGATE   = "INVESTIGATE"
    ESCALATE      = "ESCALATE"
    AUTOMATE_LITE = "AUTOMATE"
    AUTOMATE_HARD = "AUTOMATE"
    AUTOMATE      = "AUTOMATE"


@dataclass
class DFSDecision:
    score: float
    action: DFSAction
    reason: str


class DFSGuardrail:
    def __init__(
        self,
        escalate_threshold: float = 0.55,
        automate_threshold: float = 0.75,
    ) -> None:
        self.escalate_threshold = escalate_threshold
        self.automate_threshold = automate_threshold

    def decide(self, score: float) -> DFSDecision:
        if not 0.0 <= score <= 1.0:
            raise ValueError(f"DFS score must be in [0.0, 1.0], got {score}")

        if score < self.escalate_threshold:
            return DFSDecision(
                score=score,
                action=DFSAction.INVESTIGATE,
                reason=f"Score {score:.3f} below {self.escalate_threshold}. Fragile signal.",
            )

        if score < self.automate_threshold:
            return DFSDecision(
                score=score,
                action=DFSAction.ESCALATE,
                reason=f"Score {score:.3f} operational. Analyst validation required.",
            )

        return DFSDecision(
            score=score,
            action=DFSAction.AUTOMATE,
            reason=f"Score {score:.3f} above {self.automate_threshold}. High trust.",
        )