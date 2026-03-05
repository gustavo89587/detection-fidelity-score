# dfs_core/explain.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from dfs_core.scoring import DFSInputs

DEFAULT_WEIGHTS = {"s": 0.40, "t": 0.35, "b": 0.25}

DEFAULT_PENALTIES = {
    "missing_command_line": 0.25,
    "missing_parent":       0.20,
    "missing_user":         0.10,
    "missing_host":         0.05,
    "missing_process_path": 0.05,
}


@dataclass
class Explanation:
    base_score: float
    penalties_applied: Dict[str, float]
    final_score: float
    notes: List[str]


def explain_score(
    inputs,
    flags: Dict[str, bool],
    *,
    weights: Dict[str, float] = None,
    penalties: Dict[str, float] = None,
) -> Explanation:
    """
    Generic DFS explainable scoring.

    weights  defaults to DEFAULT_WEIGHTS  (s=0.40, t=0.35, b=0.25)
    penalties defaults to DEFAULT_PENALTIES
    """
    if weights is None:
        weights = DEFAULT_WEIGHTS
    if penalties is None:
        penalties = DEFAULT_PENALTIES

    # Accept both DFSInputs dataclass and plain tuple
    if isinstance(inputs, tuple):
        s, t, b = inputs
    else:
        s, t, b = inputs.s, inputs.t, inputs.b

    base = s * weights["s"] + t * weights["t"] + b * weights["b"]

    total_penalty = 0.0
    applied: Dict[str, float] = {}
    notes: List[str] = []

    for pen_key, pen_value in penalties.items():
        if not pen_key.startswith("missing_"):
            continue
        field_name = pen_key.replace("missing_", "")
        flag_name = f"has_{field_name}"
        present = flags.get(flag_name, True)
        if not present:
            total_penalty += pen_value
            applied[pen_key] = pen_value
            notes.append(f"Missing {field_name} reduces decision confidence")

    final = max(0.0, base - total_penalty)

    return Explanation(
        base_score=round(base, 4),
        penalties_applied=applied,
        final_score=round(final, 4),
        notes=notes,
    )