# dfs_core/decision_card.py
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

from dfs_core.explain import DFSExplanation


@dataclass(frozen=True)
class DecisionCard:
    """
    Minimal portable artifact: score + decision + why.
    """
    event_kind: str
    score: float
    action: str
    rationale: str

    base_score: float
    penalties: List[Dict[str, float]]
    inputs: Dict[str, float]
    notes: List[str]

    policy_name: Optional[str] = None
    event_id: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_decision_card(
    *,
    event_kind: str,
    explanation: DFSExplanation,
    action: str,
    rationale: str,
    policy_name: Optional[str] = None,
    event_id: Optional[str] = None,
    host: Optional[str] = None,
    user: Optional[str] = None,
) -> DecisionCard:
    penalties = [{"name": n, "value": float(v)} for (n, v) in explanation.penalties_applied]

    return DecisionCard(
        event_kind=event_kind,
        score=float(explanation.final_score),
        action=str(action),
        rationale=str(rationale),
        base_score=float(explanation.base_score),
        penalties=penalties,
        inputs={"s": float(explanation.inputs.s), "t": float(explanation.inputs.t), "b": float(explanation.inputs.b)},
        notes=list(explanation.notes),
        policy_name=policy_name,
        event_id=event_id,
        host=host,
        user=user,
    )
