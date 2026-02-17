# dfs_core/pipeline.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from dfs_core.explain import explain_score
from dfs_core.guardrails import DFSGuardrail
from dfs_core.policy import DFSPolicy, load_policy
from dfs_core.decision_card import DecisionCard, build_decision_card

# Feature extractor(s)
from dfs_core.features.windows_4688 import win4688_to_inputs_and_flags


@dataclass(frozen=True)
class EvaluationResult:
    card: DecisionCard
    policy: DFSPolicy


class UnknownEventKind(ValueError):
    pass


def _extract(kind: str, event: Dict[str, Any]):
    """
    Returns: (inputs, flags, normalized_kind)
    """
    k = kind.lower().strip()

    if k in ("windows-4688", "win4688", "4688"):
        inputs, flags = win4688_to_inputs_and_flags(event)
        return inputs, flags, "windows-4688"

    raise UnknownEventKind(f"Unsupported event kind: {kind}")


def evaluate_event(
    event: Dict[str, Any],
    *,
    kind: str,
    policy_path: str = "policies/default.policy.json",
    event_id: Optional[str] = None,
) -> EvaluationResult:
    """
    Main public API:
      event(dict) -> DecisionCard (explainable, SOC-safe)
    """
    policy = load_policy(policy_path)

    inputs, flags, normalized_kind = _extract(kind, event)

    exp = explain_score(inputs, flags, weights=policy.weights, penalties=policy.penalties)

    guard = DFSGuardrail(thresholds=policy.thresholds)
    decision = guard.decide(exp.final_score, inputs=inputs)

    host = (event.get("host") or {}).get("name")
    user = (event.get("user") or {}).get("name")

    card = build_decision_card(
        event_kind=normalized_kind,
        explanation=exp,
        action=decision.action.value,
        rationale=decision.rationale,
        policy_name=policy.name,
        event_id=event_id,
        host=host,
        user=user,
    )

    return EvaluationResult(card=card, policy=policy)
