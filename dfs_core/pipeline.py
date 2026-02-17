# dfs_core/pipeline.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from dfs_core.explain import explain_score
from dfs_core.guardrails import DFSGuardrail
from dfs_core.policy import DFSPolicy, load_policy
from dfs_core.decision_card import DecisionCard, build_decision_card

import dfs_core.features  # noqa: F401

# Registry
from dfs_core.features.registry import get as get_extractor


@dataclass(frozen=True)
class EvaluationResult:
    card: DecisionCard
    policy: DFSPolicy


class UnknownEventKind(ValueError):
    pass


def evaluate_event(
    event: Dict[str, Any],
    *,
    kind: str,
    policy_path: str = "policies/default.policy.json",
    event_id: Optional[str] = None,
) -> EvaluationResult:
    """
    Main DFS API

    event(dict) -> DecisionCard
    """

    # Load policy
    policy = load_policy(policy_path)

    # Get extractor from registry
    try:
        extractor = get_extractor(kind)
    except KeyError:
        raise UnknownEventKind(f"Unsupported event kind: {kind}")

    inputs, flags = extractor(event)

    # Explainable scoring
    exp = explain_score(
        inputs,
        flags,
        weights=policy.weights,
        penalties=policy.penalties
    )

    # Guardrail decision
    guard = DFSGuardrail(thresholds=policy.thresholds)
    decision = guard.decide(exp.final_score, inputs=inputs)

    host = (event.get("host") or {}).get("name")
    user = (event.get("user") or {}).get("name")

    card = build_decision_card(
        event_kind=kind,
        explanation=exp,
        action=decision.action.value,
        rationale=decision.rationale,
        policy_name=policy.name,
        event_id=event_id,
        host=host,
        user=user,
    )

    return EvaluationResult(card=card, policy=policy)
