# dfs_core/guardrails.py
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from dfs_core.scoring import DFSInputs


class DFSAction(str, Enum):
    INVESTIGATE = "Investigate"
    ESCALATE = "Escalate"
    AUTOMATE_LITE = "Automate-Lite"
    AUTOMATE_HARD = "Automate-Hard"


@dataclass(frozen=True)
class GuardrailDecision:
    score: float
    action: DFSAction
    rationale: str
    inputs: Optional[DFSInputs] = None


@dataclass(frozen=True)
class GuardrailThresholds:
    """
    4 bands (bounded automation):
      < investigate_max         => INVESTIGATE
      < escalate_max            => ESCALATE
      < automate_hard_min       => AUTOMATE_LITE
      >= automate_hard_min      => AUTOMATE_HARD
    """
    investigate_max: float = 0.55
    escalate_max: float = 0.75
    automate_hard_min: float = 0.88


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
                    "(command-line, parent chain, identity, related telemetry)."
                ),
                inputs=inputs,
            )

        if score < t.escalate_max:
            return GuardrailDecision(
                score=score,
                action=DFSAction.ESCALATE,
                rationale=(
                    "Moderate confidence. Escalate for human validation and rapid correlation "
                    "before any containment."
                ),
                inputs=inputs,
            )

        if score < t.automate_hard_min:
            return GuardrailDecision(
                score=score,
                action=DFSAction.AUTOMATE_LITE,
                rationale=(
                    "High confidence, but prefer bounded automation. "
                    "Use low-blast-radius actions first (e.g., enrich + snapshot + suspend/kill)."
                ),
                inputs=inputs,
            )

        return GuardrailDecision(
            score=score,
            action=DFSAction.AUTOMATE_HARD,
            rationale=(
                "Very high confidence. Automated containment is acceptable. "
                "Still require rollback plan and post-action validation."
            ),
            inputs=inputs,
        )
