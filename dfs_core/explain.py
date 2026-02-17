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


def explain_score(
    inputs: DFSInputs,
    context_flags: Dict[str, bool],
    weights: DFSWeights | None = None,
    penalties: DFSPenalties | None = None,
) -> DFSExplanation:
    """
    context_flags keys (expected):
      has_command_line, has_parent_process, has_user, has_host, has_process_path
    """
    w = weights or DFSWeights()
    p = penalties or DFSPenalties()

    base = weighted_base_score(inputs, w)

    applied: List[Tuple[str, float]] = []
    notes: List[str] = []

    if not context_flags.get("has_command_line", False):
        applied.append(("missing_command_line", p.missing_command_line))
        notes.append("No command-line → intent visibility collapses (high decision risk).")

    if not context_flags.get("has_parent_process", False):
        applied.append(("missing_parent", p.missing_parent))
        notes.append("No parent process → causality/chain-of-execution weakens.")

    if not context_flags.get("has_user", False):
        applied.append(("missing_user", p.missing_user))
        notes.append("No user context → accountability/baseline correlation degrades.")

    if not context_flags.get("has_host", False):
        applied.append(("missing_host", p.missing_host))
        notes.append("No host identifier → scoping & response mapping degrade.")

    if not context_flags.get("has_process_path", False):
        applied.append(("missing_process_path", p.missing_process_path))
        notes.append("No process path → harder to distinguish LOLBin vs renamed binary.")

    final = apply_penalties(base, applied)

    return DFSExplanation(
        inputs=inputs,
        base_score=base,
        penalties_applied=applied,
        final_score=final,
        notes=notes,
    )
