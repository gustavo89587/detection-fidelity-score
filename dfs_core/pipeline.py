# dfs_core/pipeline.py
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Optional, List

from core.model import DFSModel
from dfs_core.features.windows_powershell_4104 import extract


def evaluate_event(event: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate a single event and return a DecisionCard-like dict.
    Current bootstrap supports only windows-powershell-4104 (4104).
    """

    # 4104 extractor returns: (DFSInputs, flags_dict)
    inputs, flags = extract(event, policy)

    model = DFSModel()
    score_base = float(model.score(inputs))

    thresholds = policy.get("thresholds", {}) if isinstance(policy, dict) else {}
    investigate_max = float(thresholds.get("investigate_max", 0.55))
    escalate_max = float(thresholds.get("escalate_max", 0.78))
    automate_hard_min = float(thresholds.get("automate_hard_min", 0.93))

    penalties_cfg = policy.get("penalties", {}) if isinstance(policy, dict) else {}
    penalties_applied: Dict[str, float] = {}

    def _apply(name: str) -> None:
        v = penalties_cfg.get(name)
        if isinstance(v, (int, float)) and float(v) > 0:
            penalties_applied[name] = float(v)

    # Missing-context penalties (governance)
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
    # Optional: only if your extractor sets it
    if flags.get("has_command_line") is False:
        _apply("missing_command_line")

    penalty_total = float(sum(penalties_applied.values()))

    # B) Proportional degradation (SOC-friendly): avoids "zeroing" from missing context
    score_final = score_base * (1.0 - penalty_total)
    if score_final < 0.0:
        score_final = 0.0
    elif score_final > 1.0:
        score_final = 1.0

    interpretation = model.interpret(score_final)

    # Action gating uses score_final (post-penalty)
    if score_final >= automate_hard_min:
        action = "AUTOMATE"
    elif score_final > escalate_max:
        action = "ESCALATE"
    elif score_final > investigate_max:
        action = "TRIAGE"
    else:
        action = "INVESTIGATE"

    # Reasons: prioritize penalties; otherwise show high-signal indicators
    reasons: List[str] = []
    if penalties_applied:
        reasons = [k for k, _ in sorted(penalties_applied.items(), key=lambda kv: kv[1], reverse=True)]
    else:
        for k in ("looks_amsi_bypass", "looks_download_cradle", "looks_reflection", "looks_encoded", "looks_obfuscated"):
            if flags.get(k) is True:
                reasons.append(k)
    action_reason = reasons[:3]

    return {
        "kind": "windows-powershell-4104",
        "score_base": score_base,
        "penalty_total": penalty_total,
        "penalties_applied": penalties_applied,
        "score": score_final,
        "interpretation": interpretation,
        "action": action,
        "action_reason": action_reason,
        "inputs": {
            "signal": float(inputs.signal),
            "trust": float(inputs.trust),
            "overlap": float(inputs.overlap),
        },
        "flags": flags,
        "policy": {
            "weights": policy.get("weights", {}) if isinstance(policy, dict) else {},
            "thresholds": thresholds,
        },
    }


def run_score_pipeline(
    events_path: str,
    policy_path: str,
    limit: Optional[int] = None,
) -> Iterable[Dict[str, Any]]:
    """
    Minimal scoring pipeline:
      - loads policy JSON
      - reads JSONL events
      - runs 4104 extractor + DFS model
      - yields DecisionCard-like dict per event
    """
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
