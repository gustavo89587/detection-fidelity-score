
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional, List


@dataclass
class DecisionCard:
    score: float
    action: str
    kind: str
    notes: List[str] = field(default_factory=list)


class EvaluationResult:
    def __init__(self, data: dict):
        self._data = data
        self.card = DecisionCard(
            score=data["score"],
            action=data["action"],
            kind=data["kind"],
        )

    def __getitem__(self, key):
        return self._data[key]

    def get(self, key, default=None):
        return self._data.get(key, default)


def evaluate_event(
    event: Dict[str, Any],
    policy: Dict[str, Any] = None,
    *,
    kind: str = None,
    policy_path: str = None,
) -> EvaluationResult:
    """
    Evaluate a single event and return an EvaluationResult with .card.score.
    Accepts either:
      - evaluate_event(event, policy_dict)
      - evaluate_event(event, kind="...", policy_path="...")
    """
    if policy is None and policy_path:
        with open(policy_path, "r", encoding="utf-8") as f:
            policy = json.load(f)
    if policy is None:
        policy = {}

    resolved_kind = kind or (policy.get("kind") if isinstance(policy, dict) else None) or "unknown"

    from dfs_core.features.registry import load_feature
    from dfs_core import DFSModel

    try:
        extractor = load_feature(resolved_kind)
        inputs, flags = extractor(event)
    except Exception as e:
        inputs = (0.5, 0.5, 0.5)
        flags = {"error": str(e)}

    model = DFSModel()
    score_base = float(model.score(inputs))

    thresholds = policy.get("thresholds", {}) if isinstance(policy, dict) else {}
    investigate_max  = float(thresholds.get("investigate_max",  0.55))
    escalate_max     = float(thresholds.get("escalate_max",     0.78))
    automate_hard_min = float(thresholds.get("automate_hard_min", 0.93))

    penalties_cfg = policy.get("penalties", {}) if isinstance(policy, dict) else {}
    penalties_applied: Dict[str, float] = {}

    def _apply(name: str) -> None:
        v = penalties_cfg.get(name)
        if isinstance(v, (int, float)) and float(v) > 0:
            penalties_applied[name] = float(v)

    if not flags.get("has_scriptblock", True):
        _apply("missing_scriptblock")
    if not flags.get("has_user", True):
        _apply("missing_user")
    if not flags.get("has_host", True):
        _apply("missing_host")
    if not flags.get("has_parent_process", True):
        _apply("missing_parent")
    if not flags.get("has_process_path", True):
        _apply("missing_process_path")
    if flags.get("has_command_line") is False:
        _apply("missing_command_line")

    penalty_total = float(sum(penalties_applied.values()))
    score_final = max(0.0, min(1.0, score_base * (1.0 - penalty_total)))

    if score_final >= automate_hard_min:
        action = "AUTOMATE"
    elif score_final > escalate_max:
        action = "ESCALATE"
    elif score_final > investigate_max:
        action = "TRIAGE"
    else:
        action = "INVESTIGATE"

    reasons: List[str] = []
    if penalties_applied:
        reasons = [k for k, _ in sorted(penalties_applied.items(), key=lambda kv: kv[1], reverse=True)]
    else:
        for k in ("looks_amsi_bypass", "looks_download_cradle", "looks_reflection", "looks_encoded", "looks_obfuscated"):
            if flags.get(k) is True:
                reasons.append(k)

    return EvaluationResult({
        "kind": resolved_kind,
        "score_base": score_base,
        "penalty_total": penalty_total,
        "penalties_applied": penalties_applied,
        "score": score_final,
        "action": action,
        "action_reason": reasons[:3],
        "flags": flags,
    })


def run_score_pipeline(
    events_path: str,
    policy_path: str,
    limit: Optional[int] = None,
) -> Iterable[EvaluationResult]:
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = json.load(f)

    with open(events_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if limit is not None and limit > 0 and i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            yield evaluate_event(event, policy)

