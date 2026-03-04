# dfs_core/simulate.py
from __future__ import annotations

import csv
import json
import random
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Union


@dataclass(frozen=True)
class SimRow:
    run_id: int
    stage: int
    trust: str              # HIGH | MEDIUM | LOW
    decision: str           # ALLOW | REVIEW | BLOCK
    gate_triggered: int     # 0/1
    score: float            # 0..1


TRUST_LEVELS = ("HIGH", "MEDIUM", "LOW")
DECISIONS = ("ALLOW", "REVIEW", "BLOCK")


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _weighted_choice(rng: random.Random, items: List[str], weights: List[float]) -> str:
    # random.choices exists, but we keep it explicit and stable.
    x = rng.random()
    cum = 0.0
    for item, w in zip(items, weights):
        cum += w
        if x <= cum:
            return item
    return items[-1]


def _simulate_one_run(rng: random.Random, run_id: int, stages: int = 5) -> List[SimRow]:
    """
    Simple, deterministic simulator:
    - Each run produces `stages` rows (one per stage).
    - Trust distribution is roughly: HIGH 0.30, MEDIUM 0.40, LOW 0.30 (matches your console vibe).
    - Decision is derived from trust with some randomness.
    - gate_triggered = 1 when decision == BLOCK (can evolve later).
    """
    trust_weights = [0.30, 0.40, 0.30]

    rows: List[SimRow] = []
    for stage in range(1, stages + 1):
        trust = _weighted_choice(rng, list(TRUST_LEVELS), trust_weights)

        # Decision mapping (tunable)
        if trust == "HIGH":
            decision = _weighted_choice(rng, list(DECISIONS), [0.80, 0.18, 0.02])
            score = rng.uniform(0.70, 0.98)
        elif trust == "MEDIUM":
            decision = _weighted_choice(rng, list(DECISIONS), [0.35, 0.55, 0.10])
            score = rng.uniform(0.40, 0.75)
        else:  # LOW
            decision = _weighted_choice(rng, list(DECISIONS), [0.10, 0.55, 0.35])
            score = rng.uniform(0.05, 0.55)

        gate_triggered = 1 if decision == "BLOCK" else 0

        rows.append(
            SimRow(
                run_id=run_id,
                stage=stage,
                trust=trust,
                decision=decision,
                gate_triggered=gate_triggered,
                score=round(float(score), 4),
            )
        )

    return rows


def simulate_agent_pipeline(
    runs: int = 1,
    seed: Optional[int] = None,
    out_csv: Union[str, Path] = "dfs_report.csv",
) -> Dict:
    """
    Generates a CSV report and returns a summary dict.

    Contract:
    - Creates parent directories for out_csv automatically.
    - Writes UTF-8 CSV with stable column order.
    - Returns a summary shaped for CLI printing / JSON serialization.
    """
    if runs <= 0:
        raise ValueError("--runs must be >= 1")

    # Normalize output path
    out_path = Path(out_csv)
    _ensure_parent(out_path)

    # RNG
    if seed is None:
        # Still deterministic per process if you set PYTHONHASHSEED etc. —
        # but here we want explicit control. If seed is None, randomize once.
        seed = random.SystemRandom().randint(1, 2**31 - 1)
    rng = random.Random(seed)

    stages = 5
    all_rows: List[SimRow] = []
    for run_id in range(1, runs + 1):
        all_rows.extend(_simulate_one_run(rng, run_id=run_id, stages=stages))

    # Aggregate summary
    trust_counts = {k: 0 for k in TRUST_LEVELS}
    decision_counts = {k: 0 for k in DECISIONS}
    gates_triggered = 0

    for r in all_rows:
        trust_counts[r.trust] += 1
        decision_counts[r.decision] += 1
        gates_triggered += int(r.gate_triggered)

    total_rows = len(all_rows)
    gate_rate = round(gates_triggered / total_rows, 6) if total_rows else 0.0

    # Write CSV
    fieldnames = ["run_id", "stage", "trust", "decision", "gate_triggered", "score"]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in all_rows:
            w.writerow(asdict(r))

    summary = {
        "runs": runs,
        "stages": stages,
        "total_rows": total_rows,
        "seed": seed,
        "trust_counts": trust_counts,
        "gates_triggered": gates_triggered,
        "gate_rate": gate_rate,
        "out_csv": str(out_path).replace("\\", "/"),
        "decision_counts": decision_counts,
    }

    # Optional: also write a sibling run.json for traceability
    # (safe default; won't break anything if you don't want it)
    try:
        run_json = out_path.with_suffix(".run.json")
        _ensure_parent(run_json)
        run_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    except Exception:
        # Do not fail the simulation if metadata write fails
        pass

    return summary