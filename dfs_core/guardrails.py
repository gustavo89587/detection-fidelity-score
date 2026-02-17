# dfs_core/guardrails.py
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from dfs_core.scoring import DFSInputs


class DFSAction(str, Enum):
    INVESTIGATE = "Investigate"
    ESCALATE = "Escalate"
    AUTOMATE = "Automate"


@dataclass(frozen=True)
class GuardrailDecision:
    score: float
    action: DFSAction
    rationale: str
    # Optional: expose what drove the decision (useful for explainability)
    inputs: Optional[DFSInputs] = None


@dataclass(frozen=True)
class GuardrailThresholds:
    """
    Keep thresholds simple and defensible.
    - automate: only when score is high enough to justify action
    - escalate: mid band, human decision with more urgency
    - investigate: low band, recover context / gather evidence first
    """
    investigate_max: float = 0.55
    escalate_max: float = 0.75
    # >= escalate_max -> AUTOMATE


class DFSGuardrail:
    def __init__(self, thresholds: GuardrailThresholds | None = None) -> None:
        self.thresholds = thresholds or GuardrailThresholds()

    def decide(self, score: float, inputs: Optional[DFSInputs] = None) -> GuardrailDecision:
        if not (0.0 <= score <= 1.0):
            raise ValueError("score must be in [0, 1]")

        t = self.thresholds

        if score < t.investigate_max:
            return GuardrailDecision(
                score=score,
                action=DFSAction.INVESTIGATE,
                rationale=(
                    "Low decision confidence. Recover context before taking impact actions "
                    "(e.g., command-line, parent chain, identity, related telemetry)."
                ),
                inputs=inputs,
            )

        if score < t.escalate_max:
            return GuardrailDecision(
                score=score,
                action=DFSAction.ESCALATE,
                rationale=(
                    "Moderate confidence. Escalate for human validation and rapid correlation "
                    "before any automated containment."
                ),
                inputs=inputs,
            )

        return GuardrailDecision(
            score=score,
            action=DFSAction.AUTOMATE,
            rationale=(
                "High confidence. Signal likely sustains an automated action with acceptable risk. "
                "Prefer bounded actions first (kill process / isolate host) with rollback plans."
            ),
            inputs=inputs,
        )
