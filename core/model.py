"""
Detection Fidelity Score (DFS) — core model

DFS is a compact reliability model for detection signals:
    DFS = S * T * B

Where:
- S = Signal Strength (0..1)        → how strong the signal is for the behavior
- T = Telemetry Stability (0..1)    → how stable/available/consistent the telemetry is
- B = Behavioral Robustness (0..1)  → how resilient the behavior model is to drift/adaptation

Design goals:
- Deterministic
- Validated inputs (0..1)
- Easy to embed in notebooks, scripts, pipelines
- Clear extension points (bands, thresholds, curves, metadata)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Tuple, Union


# -----------------------------
# Exceptions
# -----------------------------

class DFSValidationError(ValueError):
    """Raised when inputs or configuration are invalid."""


# -----------------------------
# Bands / Interpretation
# -----------------------------

class DFSBand(str, Enum):
    HIGH_TRUST = "High Trust"
    OPERATIONAL = "Operational"
    FRAGILE = "Fragile"
    UNRELIABLE = "Unreliable"


@dataclass(frozen=True)
class DFSThresholds:
    """
    Band thresholds. Must be monotonically decreasing.

    Example:
        high_trust = 0.80
        operational = 0.60
        fragile = 0.40
    """
    high_trust: float = 0.80
    operational: float = 0.60
    fragile: float = 0.40

    def __post_init__(self) -> None:
        _validate_unit_interval(self.high_trust, "threshold.high_trust")
        _validate_unit_interval(self.operational, "threshold.operational")
        _validate_unit_interval(self.fragile, "threshold.fragile")
        if not (self.high_trust >= self.operational >= self.fragile):
            raise DFSValidationError(
                "Thresholds must be monotonic: high_trust >= operational >= fragile"
            )

    def band(self, score: float) -> DFSBand:
        _validate_unit_interval(score, "score")
        if score >= self.high_trust:
            return DFSBand.HIGH_TRUST
        if score >= self.operational:
            return DFSBand.OPERATIONAL
        if score >= self.fragile:
            return DFSBand.FRAGILE
        return DFSBand.UNRELIABLE


# -----------------------------
# Core model
# -----------------------------

@dataclass(frozen=True)
class DFSInputs:
    """
    Core DFS inputs (S, T, B), each in [0..1].

    Keep this minimal and stable: it's the "API surface" of your scoring model.
    """
    signal_strength: float
    telemetry_stability: float
    behavioral_robustness: float

    def __post_init__(self) -> None:
        _validate_unit_interval(self.signal_strength, "signal_strength")
        _validate_unit_interval(self.telemetry_stability, "telemetry_stability")
        _validate_unit_interval(self.behavioral_robustness, "behavioral_robustness")


@dataclass(frozen=True)
class DFSResult:
    """
    Output of DFS scoring.
    """
    score: float
    band: DFSBand
    inputs: DFSInputs
    # Optional: you can store arbitrary metadata without changing the math layer.
    meta: Dict[str, Union[str, float, int, bool]] = field(default_factory=dict)


@dataclass(frozen=True)
class DFSModel:
    """
    DFS scoring engine.

    Default math:
        DFS = S * T * B

    Extension points:
    - thresholds (band mapping)
    - you can later add alternative aggregations (e.g., min-gating) without breaking callers
    """
    thresholds: DFSThresholds = field(default_factory=DFSThresholds)

    def score(self, inputs: DFSInputs, *, meta: Optional[Dict[str, Union[str, float, int, bool]]] = None) -> DFSResult:
        s = inputs.signal_strength
        t = inputs.telemetry_stability
        b = inputs.behavioral_robustness

        value = _clamp01(s * t * b)
        band = self.thresholds.band(value)

        return DFSResult(
            score=value,
            band=band,
            inputs=inputs,
            meta=dict(meta or {}),
        )

    def score_raw(self, s: float, t: float, b: float, *, meta: Optional[Dict[str, Union[str, float, int, bool]]] = None) -> DFSResult:
        return self.score(DFSInputs(s, t, b), meta=meta)


# -----------------------------
# Degradation curves
# -----------------------------

class DegradationMode(str, Enum):
    """
    Conceptual degradation domains (maps to your README language).
    """
    LOSS = "Loss"
    DISTORTION = "Distortion"
    DRIFT = "Drift"


@dataclass(frozen=True)
class DegradationCurvePoint:
    x: float  # usually 0..1 (severity)
    telemetry_stability: float
    dfs: float
    band: DFSBand


def build_degradation_curve(
    model: DFSModel,
    *,
    base_signal_strength: float,
    base_behavioral_robustness: float,
    base_telemetry_stability: float,
    severity_points: int = 21,
    telemetry_drop: float = 0.55,
    mode: DegradationMode = DegradationMode.DISTORTION,
    meta: Optional[Dict[str, Union[str, float, int, bool]]] = None,
) -> List[DegradationCurvePoint]:
    """
    Builds a simple degradation curve by degrading Telemetry Stability (T) as severity increases.

    This is intentionally "boring" and deterministic:
    - severity x goes from 0..1
    - T(x) = base_T - telemetry_drop * x   (clamped to [0..1])
    - DFS = S * T(x) * B

    You can later replace this with empirical curves, piecewise models, or environment-specific functions.
    """
    _validate_unit_interval(base_signal_strength, "base_signal_strength")
    _validate_unit_interval(base_behavioral_robustness, "base_behavioral_robustness")
    _validate_unit_interval(base_telemetry_stability, "base_telemetry_stability")

    if severity_points < 2:
        raise DFSValidationError("severity_points must be >= 2")
    if telemetry_drop < 0:
        raise DFSValidationError("telemetry_drop must be >= 0")

    points: List[DegradationCurvePoint] = []
    for i in range(severity_points):
        x = i / (severity_points - 1)  # 0..1
        t = _clamp01(base_telemetry_stability - (telemetry_drop * x))

        r = model.score_raw(
            base_signal_strength,
            t,
            base_behavioral_robustness,
            meta={
                **(meta or {}),
                "degradation_mode": mode.value,
                "severity": x,
            },
        )
        points.append(
            DegradationCurvePoint(
                x=x,
                telemetry_stability=t,
                dfs=r.score,
                band=r.band,
            )
        )
    return points


# -----------------------------
# Utilities
# -----------------------------

def _validate_unit_interval(value: float, name: str) -> None:
    if not isinstance(value, (int, float)):
        raise DFSValidationError(f"{name} must be a number.")
    if value < 0.0 or value > 1.0:
        raise DFSValidationError(f"{name} must be in [0..1]. Got: {value}")


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)


# -----------------------------
# Minimal self-test (optional)
# -----------------------------

def _demo() -> None:
    m = DFSModel()

    # Example: Windows 4688 - Encoded PS
    res = m.score_raw(0.82, 0.60, 0.75, meta={"name": "Windows 4688 - Encoded PS"})
    print(res)

    curve = build_degradation_curve(
        m,
        base_signal_strength=0.82,
        base_telemetry_stability=0.60,
        base_behavioral_robustness=0.75,
        telemetry_drop=0.55,
        severity_points=11,
        mode=DegradationMode.DISTORTION,
    )
    for p in curve:
        print(p)


if __name__ == "__main__":
    _demo()
