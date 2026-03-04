# dfs_core/evaluate.py
from __future__ import annotations

import json
import random
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# =========================
# Data contracts
# =========================

@dataclass(frozen=True)
class Policy:
    name: str
    weights: Dict[str, float]      # s,t,b (normalized)
    penalties: Dict[str, float]    # missing_* penalties
    thresholds: Dict[str, float]   # investigate_max, escalate_max, automate_hard_min


@dataclass(frozen=True)
class PolicyEval:
    policy_name: str
    total_events: int

    # base score distribution (0..1)
    avg_score: float
    median_score: float
    p10: float
    p90: float

    # C: criticality-weighted
    weighted_avg_score: float

    # D: operational cost
    op_cost_avg: float
    cost_adjusted_score: float

    # bucket rates/counts (operationally meaningful)
    investigate_rate: float
    escalate_rate: float
    automate_rate: float
    investigate_count: int
    escalate_count: int
    automate_count: int

    # diagnostics
    missing_counts: Dict[str, int]

    # B: bootstrap stability over dataset (on cost_adjusted_score)
    stability: Dict[str, float]


# =========================
# Loading
# =========================

def load_policy(path: Path) -> Policy:
    obj = json.loads(path.read_text(encoding="utf-8"))

    name = str(obj.get("name") or path.stem)

    weights = obj.get("weights") or {}
    penalties = obj.get("penalties") or {}
    thresholds = obj.get("thresholds") or {}

    if not isinstance(weights, dict) or not isinstance(penalties, dict) or not isinstance(thresholds, dict):
        raise ValueError(f"Invalid policy schema: {path}")

    w = {
        "s": float(weights.get("s", 1.0)),
        "t": float(weights.get("t", 0.0)),
        "b": float(weights.get("b", 0.0)),
    }
    s = w["s"] + w["t"] + w["b"]
    if s <= 0:
        w = {"s": 1.0, "t": 0.0, "b": 0.0}
    else:
        w = {k: v / s for k, v in w.items()}

    p = {str(k): float(v) for k, v in penalties.items()}

    th = {
        "investigate_max": float(thresholds.get("investigate_max", 0.55)),
        "escalate_max": float(thresholds.get("escalate_max", 0.78)),
        "automate_hard_min": float(thresholds.get("automate_hard_min", 0.93)),
    }

    return Policy(name=name, weights=w, penalties=p, thresholds=th)


def load_jsonl_events(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events


# =========================
# Helpers: event access
# =========================

def deep_get(d: Dict[str, Any], path: List[str]) -> Optional[Any]:
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def is_missing(x: Any) -> bool:
    if x is None:
        return True
    if isinstance(x, str) and not x.strip():
        return True
    return False


# =========================
# Feature extraction for your JSONL schema
# Top-level keys: event, host, user, winlog
# =========================

def event_completeness_flags(ev: Dict[str, Any]) -> Dict[str, bool]:
    """
    Maps to your policy penalty keys.
    Tuned for: ['event','host','user','winlog'] with winlog.event_data.*.
    """
    command_line = deep_get(ev, ["winlog", "event_data", "CommandLine"])
    scriptblock = deep_get(ev, ["winlog", "event_data", "ScriptBlockText"])
    parent_image = deep_get(ev, ["winlog", "event_data", "ParentImage"])
    process_image = deep_get(ev, ["winlog", "event_data", "Image"])

    user_name = deep_get(ev, ["user", "name"]) or deep_get(ev, ["winlog", "user", "name"])
    host_name = deep_get(ev, ["host", "name"]) or deep_get(ev, ["winlog", "computer_name"])

    return {
        "missing_command_line": is_missing(command_line),
        "missing_parent": is_missing(parent_image),
        "missing_user": is_missing(user_name),
        "missing_host": is_missing(host_name),
        "missing_process_path": is_missing(process_image),
        "missing_scriptblock": is_missing(scriptblock),
    }


# =========================
# C: Criticality weighting
# =========================

def event_criticality_weight(ev: Dict[str, Any]) -> float:
    """
    Returns weight in [0.5..2.0], default 1.0.
    If event.severity or event.risk_score exist, uses them.
    Otherwise uses a pragmatic 4104 heuristic: longer ScriptBlockText => slightly higher weight.
    """
    sev = deep_get(ev, ["event", "severity"])
    if isinstance(sev, (int, float)):
        sev_f = float(sev)  # assume 1..10
        return max(0.5, min(2.0, 0.5 + (sev_f / 10.0) * 1.5))

    risk = deep_get(ev, ["event", "risk_score"])
    if isinstance(risk, (int, float)):
        risk_f = float(risk)  # assume 0..100
        return max(0.5, min(2.0, 0.5 + (risk_f / 100.0) * 1.5))

    sb = deep_get(ev, ["winlog", "event_data", "ScriptBlockText"])
    if isinstance(sb, str) and sb:
        # length heuristic: 0..4000 chars mapped to 0.9..1.4
        L = min(len(sb), 4000)
        w = 0.9 + (L / 4000.0) * 0.5
        return max(0.5, min(2.0, w))

    return 1.0


# =========================
# D: Operational cost
# =========================

DEFAULT_BUCKET_COST: Dict[str, float] = {
    "INVESTIGATE": 3.0,
    "ESCALATE": 1.5,
    "AUTOMATE": 0.4,
}


def bucket_cost(bucket: str, cost_map: Optional[Dict[str, float]] = None) -> float:
    cm = cost_map or DEFAULT_BUCKET_COST
    return float(cm.get(bucket, 1.5))


# =========================
# Scoring & classification
# =========================

def score_event(policy: Policy, ev: Dict[str, Any]) -> Tuple[float, Dict[str, bool]]:
    """
    Minimal policy-aligned scoring:
    - Start 1.0
    - Subtract penalties for missing fields (clamp 0..1)
    - Keep slots for s/t/b (currently all share the same base component)
    """
    flags = event_completeness_flags(ev)
    penalty_sum = 0.0
    for key, missing in flags.items():
        if missing:
            penalty_sum += float(policy.penalties.get(key, 0.0))

    base = 1.0 - penalty_sum
    base = max(0.0, min(1.0, base))

    # keep structure for future: t (timeliness), b (behavior) can diverge later
    final = (
        policy.weights["s"] * base +
        policy.weights["t"] * base +
        policy.weights["b"] * base
    )
    final = max(0.0, min(1.0, final))
    return round(final, 6), flags


def classify(policy: Policy, score: float) -> str:
    inv = policy.thresholds["investigate_max"]
    esc = policy.thresholds["escalate_max"]
    auto = policy.thresholds["automate_hard_min"]

    if score <= inv:
        return "INVESTIGATE"
    if score <= esc:
        return "ESCALATE"
    if score >= auto:
        return "AUTOMATE"
    return "ESCALATE"


def percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if p <= 0:
        return float(sorted_vals[0])
    if p >= 100:
        return float(sorted_vals[-1])
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return float(sorted_vals[f])
    d0 = sorted_vals[f] * (c - k)
    d1 = sorted_vals[c] * (k - f)
    return float(d0 + d1)


# =========================
# B: Bootstrap stability
# =========================

def bootstrap_stats(
    stat_fn: Callable[[List[Dict[str, Any]]], float],
    events: List[Dict[str, Any]],
    iterations: int = 200,
    seed: int = 12345,
) -> Dict[str, float]:
    if not events or iterations <= 0:
        return {"mean": 0.0, "std": 0.0, "p05": 0.0, "p95": 0.0, "iterations": 0}

    rng = random.Random(seed)
    n = len(events)
    vals: List[float] = []

    for _ in range(iterations):
        sample = [events[rng.randrange(n)] for _ in range(n)]
        vals.append(float(stat_fn(sample)))

    vals.sort()
    mean = sum(vals) / len(vals)
    var = sum((x - mean) ** 2 for x in vals) / (len(vals) - 1) if len(vals) > 1 else 0.0
    std = var ** 0.5
    p05 = vals[int(0.05 * (len(vals) - 1))]
    p95 = vals[int(0.95 * (len(vals) - 1))]

    return {
        "mean": round(mean, 6),
        "std": round(std, 6),
        "p05": round(p05, 6),
        "p95": round(p95, 6),
        "iterations": int(iterations),
    }


# =========================
# Evaluation
# =========================

def evaluate_policy_on_events(
    policy: Policy,
    events: List[Dict[str, Any]],
    *,
    alpha_op_cost: float = 0.15,
    bootstrap_iterations: int = 200,
    bootstrap_seed: int = 12345,
    cost_map: Optional[Dict[str, float]] = None,
) -> Tuple[PolicyEval, List[Dict[str, Any]]]:
    """
    Returns:
      - PolicyEval metrics (for ranking/compare)
      - labeled list per-event (score, bucket, missing, criticality_weight, op_cost)
        (useful if you want to save samples)
    """
    scores: List[float] = []
    labeled: List[Dict[str, Any]] = []

    # missing diagnostics: count only keys present in policy penalties
    missing_counts: Dict[str, int] = {k: 0 for k in policy.penalties.keys()}

    investigate = escalate = automate = 0

    weighted_sum = 0.0
    weight_total = 0.0
    cost_sum = 0.0

    for ev in events:
        s, flags = score_event(policy, ev)
        bucket = classify(policy, s)

        w = float(event_criticality_weight(ev))
        c = float(bucket_cost(bucket, cost_map))

        scores.append(s)

        # missing counts
        for k, missing in flags.items():
            if missing and k in missing_counts:
                missing_counts[k] += 1

        # bucket counts
        if bucket == "INVESTIGATE":
            investigate += 1
        elif bucket == "AUTOMATE":
            automate += 1
        else:
            escalate += 1

        # C + D aggregation (weighted)
        weighted_sum += w * s
        cost_sum += w * c
        weight_total += w

        labeled.append(
            {
                "score": s,
                "bucket": bucket,
                "criticality_weight": round(w, 6),
                "op_cost": round(c, 6),
                "missing": {k: v for k, v in flags.items() if v},
            }
        )

    total = len(events)

    s_sorted = sorted(scores)
    avg = round(sum(scores) / total, 6) if total else 0.0
    med = round(percentile(s_sorted, 50), 6)
    p10 = round(percentile(s_sorted, 10), 6)
    p90 = round(percentile(s_sorted, 90), 6)

    weighted_avg = round((weighted_sum / weight_total), 6) if weight_total else 0.0
    op_cost_avg = round((cost_sum / weight_total), 6) if weight_total else 0.0
    cost_adjusted = round(weighted_avg - (alpha_op_cost * op_cost_avg), 6)

    inv_rate = round(investigate / total, 6) if total else 0.0
    esc_rate = round(escalate / total, 6) if total else 0.0
    auto_rate = round(automate / total, 6) if total else 0.0

    # Bootstrap on cost_adjusted_score for stability (B)
    def _stat(sample_events: List[Dict[str, Any]]) -> float:
        ws = wt = cs = 0.0
        for ev2 in sample_events:
            s2, _ = score_event(policy, ev2)
            b2 = classify(policy, s2)
            w2 = float(event_criticality_weight(ev2))
            c2 = float(bucket_cost(b2, cost_map))
            ws += w2 * s2
            cs += w2 * c2
            wt += w2
        if wt <= 0:
            return 0.0
        return (ws / wt) - (alpha_op_cost * (cs / wt))

    stability = bootstrap_stats(
        _stat,
        events,
        iterations=bootstrap_iterations,
        seed=bootstrap_seed,
    )

    metrics = PolicyEval(
        policy_name=policy.name,
        total_events=total,
        avg_score=avg,
        median_score=med,
        p10=p10,
        p90=p90,
        weighted_avg_score=weighted_avg,
        op_cost_avg=op_cost_avg,
        cost_adjusted_score=cost_adjusted,
        investigate_rate=inv_rate,
        escalate_rate=esc_rate,
        automate_rate=auto_rate,
        investigate_count=investigate,
        escalate_count=escalate,
        automate_count=automate,
        missing_counts=missing_counts,
        stability=stability,
    )
    return metrics, labeled


def to_dict(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    return obj