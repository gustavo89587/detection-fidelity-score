# dfs_core/scoring.py
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class DFSInputs:
    signal: float  # Signal Strength (also accessible as .s)
    overlap: float  # Behavioral Robustness (also accessible as .b)
    trust: float   # Telemetry Stability (also accessible as .t)

    @property
    def s(self) -> float:
        return self.signal

    @property
    def t(self) -> float:
        return self.trust

    @property
    def b(self) -> float:
        return self.overlap


def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def classify(score: float, t_high: float, t_med: float) -> str:
    if score >= t_high:
        return "HIGH"
    if score >= t_med:
        return "MEDIUM"
    return "LOW"


def calculate_score(
    loss: float,
    distortion: float,
    drift: float,
    *,
    w_loss: float,
    w_distortion: float,
    w_drift: float,
    floor: float,
    penalty_scale: float,
    enable_drift_gate: bool,
):
    loss = clamp01(loss)
    distortion = clamp01(distortion)
    drift = clamp01(drift)
    base = (loss * w_loss) + (distortion * w_distortion) + (drift * w_drift)
    severity = (
        max(0.0, floor - loss) +
        max(0.0, floor - distortion) +
        max(0.0, floor - drift)
    )
    penalty = penalty_scale * severity
    score = max(0.0, base - penalty)
    gate_triggered = False
    if enable_drift_gate and drift < floor:
        gate_triggered = True
        score = min(score, 0.49)
    return round(score, 4), round(base, 4), round(penalty, 4), gate_triggered
