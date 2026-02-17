# dfs_core/explain.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from dfs_core.scoring import DFSInputs


@dataclass(frozen=True)
class DFSWeights:
    """
    Weights for S/T/B contributions.
    Keep it simple and transparent.
    """
    s: float = 0.40
    t: float = 0.35
    b: float = 0.25

    def normalized(self) -> "DFSWeights":
        total = self.s + self.t + self.b
        if total <= 0:
            raise ValueError("weights total must be > 0")
        return DFSWeights(self.s / total, self.t / total, self.b / total)


@dataclass(frozen=True)
class DFSPenalties:
    """
    Field-level penalties (0..1) applied AFTER base score.
    penalty = 0.15 means 'reduce score by 15% multiplicatively' when condition triggers.
    """
    missing_command_line: float = 0.25
    missing_parent: float = 0.20
    missing_user: float = 0.10
    missing_host: float = 0.05
    missing_process_path: float = 0.05


@dataclass(frozen=True)
class DFSExplanation:
    inputs: DFSInputs
    base_score: float
    penalties_applied: List[Tuple[str, float]]
    final_score: float
    notes: List[str]


def weighted_base_score(inputs: DFSInputs, weights: DFSWeights) -> float:
    w = weights.normalized()
    score = (inputs.s * w.s) + (inputs.t * w.t) + (inputs.b * w.b)
    # clamp
    return max(0.0, min(1.0, float(score)))


def apply_penalties(base_score: float, penalties: List[Tuple[str, float]]) -> float:
    """
    Multiplicative penalties (survivability mindset):
    final = base * Π(1 - p_i)
    """
    score = base_score
    for _, p in penalties:
        if p < 0 or p > 1:
            raise ValueError("penalty must be in [0, 1]")
        score *= (1.0 - p)
    return max(0.0, min(1.0, float(score)))

from dataclasses import dataclass
from typing import Dict, List

from dfs_core.scoring import DFSInputs


@dataclass
class Explanation:
    base_score: float
    penalties_applied: Dict[str, float]
    final_score: float
    notes: List[str]


def explain_score(
    inputs: DFSInputs,
    flags: Dict[str, bool],
    *,
    weights: Dict[str, float],
    penalties: Dict[str, float],
) -> Explanation:
    """
    Generic DFS explainable scoring.

    penalties = {
        "missing_scriptblock": 0.35,
        "missing_source_ip": 0.30,
        ...
    }

    flags = {
        "has_scriptblock": True,
        "has_source_ip": False,
        ...
    }

    If penalty key = "missing_X"
    it will check flag "has_X"
    """

    # base score
    base = (
        inputs.s * weights["s"]
        + inputs.t * weights["t"]
        + inputs.b * weights["b"]
    )

    total_penalty = 0.0
    applied = {}
    notes = []

    for pen_key, pen_value in penalties.items():
        if not pen_key.startswith("missing_"):
            continue

        field = pen_key.replace("missing_", "")
        flag_name = f"has_{field}"

        present = flags.get(flag_name, True)

        if not present:
            total_penalty += pen_value
            applied[pen_key] = pen_value
            notes.append(f"Missing {field} reduces decision confidence")

    final = max(0.0, base - total_penalty)

    return Explanation(
        base_score=base,
        penalties_applied=applied,
        final_score=final,
        notes=notes,
    )


