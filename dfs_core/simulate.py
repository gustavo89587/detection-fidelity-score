# dfs_core/simulate.py
from __future__ import annotations

import csv
import random
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .engine import DecisionReliabilityEngine


DEFAULT_STAGES = ["PLAN", "RETRIEVE", "TOOL_REQUEST", "EXECUTE", "POST_CHECK"]


def _bool_from_p(p: float, rng: random.Random) -> bool:
    return rng.random() < p


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _draw_metric(rng: random.Random, lo: float = 0.05, hi: float = 0.95) -> float:
    return round(_clamp01(rng.uniform(lo, hi)), 2)


def _row_order() -> List[str]:
    # Keep original columns + add decision fields at the end (compatible)
    return [
        "ts",
        "run_id",
        "step",
        "stage",
        "loss",
        "distortion",
        "drift",
        "base",
        "penalty",
        "gate_triggered",
        "reasons",
        "score",
        "trust",
        "prompt_leak_attempt",
        "indirect_injection",
        "shadow_ai",
        "delegation_depth",
        "structural_risk",
        "structural_gate",
        "decision",
        "decision_reason",
    ]


def simulate_agent_pipeline(
    *,
    runs: int = 40,
    seed: int = 7,
    stages: Optional[List[str]] = None,
    out_csv: str = "dfs_agent_timeline.csv",
) -> Dict[str, Any]:
    """
    Generates a synthetic agent timeline and scores each step with DFS.
    Output CSV includes unified decision fields: decision + decision_reason.

    Returns a summary dict used by CLI printing.
    """
    stages = stages or list(DEFAULT_STAGES)
    rng = random.Random(seed)

    engine = DecisionReliabilityEngine()

    trust_counts: Dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    decision_counts: Dict[str, int] = {"ALLOW": 0, "REVIEW": 0, "BLOCK": 0}

    gates_triggered = 0
    total_rows = 0

    # simple "session-ish" variable: delegation depth tends to grow with run/steps
    # This is synthetic; you can later replace with state-aware session logic.
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_row_order())
        writer.writeheader()

        for run_id in range(1, runs + 1):
            delegation_depth = 1

            for step_idx, stage in enumerate(stages, start=1):
                # ---- Synthetic signals (tune these probabilities to force demos) ----
                # Low probabilities by default; spikes occasionally.
                prompt_leak_attempt = _bool_from_p(0.03 if stage != "EXECUTE" else 0.06, rng)
                indirect_injection = _bool_from_p(0.05 if stage == "RETRIEVE" else 0.03, rng)
                shadow_ai = _bool_from_p(0.02, rng)

                # Depth grows mostly after TOOL_REQUEST / EXECUTE
                if stage in ("TOOL_REQUEST", "EXECUTE") and _bool_from_p(0.45, rng):
                    delegation_depth += 1

                signals = {
                    "prompt_leak_attempt": prompt_leak_attempt,
                    "indirect_injection": indirect_injection,
                    "shadow_ai": shadow_ai,
                    "delegation_depth": float(delegation_depth),
                    # IMPORTANT: decision layer uses this
                    "stage": stage,
                    # Optional; leave empty unless you model action types later
                    # "action": "ISOLATE_HOST",
                }

                # ---- Metrics (0..1) ----
                loss = _draw_metric(rng)
                distortion = _draw_metric(rng)
                drift = _draw_metric(rng)

                snapshot = {
                    "loss": loss,
                    "distortion": distortion,
                    "drift": drift,
                    "signals": signals,
                }

                result = engine.evaluate(snapshot)

                # Counts
                trust_counts[result.trust] = trust_counts.get(result.trust, 0) + 1
                decision_counts[result.decision] = decision_counts.get(result.decision, 0) + 1
                gates_triggered += int(result.gate_triggered)
                total_rows += 1

                # CSV row
                row = {
                    "ts": "",  # keep empty for compatibility (you can add ISO timestamps later)
                    "run_id": run_id,
                    "step": step_idx,
                    "stage": stage,
                    "loss": loss,
                    "distortion": distortion,
                    "drift": drift,
                    "base": round(result.base, 2),
                    "penalty": round(result.penalty, 2),
                    "gate_triggered": int(result.gate_triggered),
                    "reasons": result.reasons,
                    "score": round(result.score, 2),
                    "trust": result.trust,
                    "prompt_leak_attempt": 1 if prompt_leak_attempt else 0,
                    "indirect_injection": 1 if indirect_injection else 0,
                    "shadow_ai": 1 if shadow_ai else 0,
                    "delegation_depth": int(delegation_depth),
                    "structural_risk": round(result.structural_risk, 2),
                    "structural_gate": 1 if result.structural_gate else 0,
                    # NEW (infra-layer outputs)
                    "decision": result.decision,
                    "decision_reason": result.decision_reason,
                }

                writer.writerow(row)

    gate_rate = round((gates_triggered / total_rows) * 100.0, 1) if total_rows else 0.0

    # Keep old keys so your CLI output stays compatible
    return {
        "runs": runs,
        "stages": len(stages),
        "total_rows": total_rows,
        "seed": seed,
        "trust_counts": trust_counts,
        "gates_triggered": gates_triggered,
        "gate_rate": gate_rate,
        "out_csv": out_csv,
        # Extra (won't break anything; CLI may choose to print later)
        "decision_counts": decision_counts,
    }