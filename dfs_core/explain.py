# dfs_core/explain.py
from __future__ import annotations
from dataclasses import dataclass
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
    penalties_applied: List[Tuple[str, float]]
    final_score: float
    notes: List[str]


def explain_score(
    inputs,
    flags: Dict[str, bool],
    *,
    weights: Dict[str, float] = None,
    penalties: Dict[str, float] = None,
) -> Explanation:
    if weights is None:
        weights = DEFAULT_WEIGHTS
    if penalties is None:
        penalties = DEFAULT_PENALTIES

    if isinstance(inputs, tuple):
        s, t, b = inputs
    elif hasattr(inputs, 'signal'):
        s, t, b = inputs.signal, inputs.trust, inputs.overlap
    else:
        s, t, b = inputs.s, inputs.t, inputs.b

    base = s * weights["s"] + t * weights["t"] + b * weights["b"]

    applied: List[Tuple[str, float]] = []
    notes: List[str] = []

    for pen_key, pen_value in penalties.items():
        if not pen_key.startswith("missing_"):
            continue
        field_name = pen_key.replace("missing_", "")
        # check has_parent_process for missing_parent
        if field_name == "parent":
            flag_name = "has_parent_process"
        else:
            flag_name = f"has_{field_name}"
        present = flags.get(flag_name, True)
        if not present:
            applied.append((pen_key, pen_value))
            notes.append(f"Missing {field_name} reduces decision confidence")

    total_penalty = sum(v for _, v in applied)
    final = max(0.0, base - total_penalty)

    return Explanation(
        base_score=round(base, 4),
        penalties_applied=applied,
        final_score=round(final, 4),
        notes=notes,
    )
