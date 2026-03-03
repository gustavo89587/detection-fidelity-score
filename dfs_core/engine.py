# dfs_core/engine.py
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, List, Tuple


# ----------------------------
# Core scoring primitives
# ----------------------------

def calculate_score(
    loss: float,
    distortion: float,
    drift: float,
    *,
    w_loss: float = 0.30,
    w_distortion: float = 0.40,
    w_drift: float = 0.30,
    floor: float = 0.30,
    penalty_scale: float = 0.40,
    enable_drift_gate: bool = True,
) -> Tuple[float, float, float, int]:
    """
    Returns: (score, base, penalty, gate_triggered)
    - base: weighted sum
    - penalty: penalty_scale * severity
    - gate: if drift < floor and enable_drift_gate, cap score to <= 0.49
    """
    base = (loss * w_loss) + (distortion * w_distortion) + (drift * w_drift)

    severity = 0.0
    severity += max(0.0, floor - loss)
    severity += max(0.0, floor - distortion)
    severity += max(0.0, floor - drift)

    penalty = penalty_scale * severity
    score = max(0.0, base - penalty)

   
    if enable_drift_gate and drift < floor:
        gate_triggered = 1
        score = min(0.59, score)  # permite MEDIUM, não força LOW
    else:
        gate_triggered = 0
    return score, base, penalty, gate_triggered


def classify(score: float, *, t_high: float = 0.70, t_med: float = 0.45) -> str:
    if score >= t_high:
        return "HIGH"
    if score >= t_med:
        return "MEDIUM"
    return "LOW"


def reason_codes(loss: float, distortion: float, drift: float, *, floor: float = 0.30) -> str:
    reasons: List[str] = []
    if loss < floor:
        reasons.append("LOSS_BELOW_FLOOR")
    if distortion < floor:
        reasons.append("DISTORTION_BELOW_FLOOR")
    if drift < floor:
        reasons.append("DRIFT_BELOW_FLOOR")
    return "OK" if not reasons else "|".join(reasons)


# ----------------------------
# Policy + Calibration Profiles
# ----------------------------

@dataclass
class DFSPolicy:
    w_loss: float = 0.30
    w_distortion: float = 0.40
    w_drift: float = 0.30

    # Thresholds & penalty
    floor: float = 0.30
    penalty_scale: float = 0.40
    enable_drift_gate: bool = True

    # Trust thresholds
    t_high: float = 0.70
    t_med: float = 0.45


@dataclass(frozen=True)
class DFSMode:
    """
    Simple calibration knobs (kept intentionally small).
    - floor/penalty: controls score conservatism
    - structural_gate_threshold: when governance blocks EXECUTE
    - structural_drift_scale: how much structural risk degrades drift quality
    """
    name: str
    floor: float
    penalty_scale: float
    structural_gate_threshold: float
    structural_drift_scale: float


BALANCED = DFSMode(
    name="balanced",
    floor=0.20,
    penalty_scale=0.30,
    structural_gate_threshold=0.80,
    structural_drift_scale=0.15,
)

STRICT = DFSMode(
    name="strict",
    floor=0.30,
    penalty_scale=0.40,
    structural_gate_threshold=0.70,
    structural_drift_scale=0.25,
)


def _get_mode(mode: str | None) -> DFSMode:
    m = (mode or "balanced").strip().lower()
    if m in ("strict", "enterprise", "hardened"):
        return STRICT
    return BALANCED


# ----------------------------
# Result
# ----------------------------

@dataclass
class DecisionResult:
    score: float
    trust: str
    base: float
    penalty: float
    gate_triggered: int
    reasons: str

    structural_risk: float = 0.0
    structural_gate: bool = False

    # Unified action decision
    decision: str = "ALLOW"          # ALLOW | REVIEW | BLOCK
    decision_reason: str = "OK"      # single reason code

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ----------------------------
# Engine
# ----------------------------

class DecisionReliabilityEngine:
    def __init__(self, policy: DFSPolicy | None = None, *, mode: str | None = None):
        self.policy = policy or DFSPolicy()
        self.policy.t_high = 0.70
        self.policy.t_med = 0.45
        self.mode = _get_mode(mode)

        # Apply calibration (simple, predictable)
        self.policy.floor = self.mode.floor
        self.policy.penalty_scale = self.mode.penalty_scale

        # Governance threshold (separate from score)
        self.structural_gate_threshold = self.mode.structural_gate_threshold

        # Structural risk impact on drift quality
        self.structural_drift_scale = self.mode.structural_drift_scale

        # Optional: destructive actions list
        self.destructive_actions = {
            "ISOLATE_HOST",
            "DISABLE_USER",
            "BLOCK_IP",
            "KILL_PROCESS",
            "QUARANTINE_FILE",
            "DELETE_RESOURCE",
            "TERMINATE_INSTANCE",
        }

    def _compute_structural_risk(self, signals: dict[str, Any]) -> float:
        prompt_leak = 1.0 if signals.get("prompt_leak_attempt") else 0.0
        indirect_injection = 1.0 if signals.get("indirect_injection") else 0.0
        shadow_ai = 1.0 if signals.get("shadow_ai") else 0.0
        delegation_depth = float(signals.get("delegation_depth", 1))

        structural_risk = 0.0
        structural_risk += 0.55 * prompt_leak
        structural_risk += 0.35 * indirect_injection
        structural_risk += 0.10 * shadow_ai
        structural_risk += 0.02 * max(0.0, delegation_depth - 1.0)
        return min(1.0, structural_risk)

    def _decide(
        self,
        trust: str,
        gate_triggered: int,
        structural_gate: bool,
        signals: dict[str, Any],
    ) -> tuple[str, str]:
        stage = str(signals.get("stage", "")).upper()
        action = str(signals.get("action", "")).upper()
        destructive = action in self.destructive_actions

        # Governance dominates on execution (or destructive action)
        if structural_gate and (stage == "EXECUTE" or destructive):
            return "BLOCK", "STRUCTURAL_RISK_AT_EXECUTE"

        # Drift gate => no autonomy
        if gate_triggered == 1:
            return "REVIEW", "DRIFT_GATE_TRIGGERED"

        # Trust gating
        if trust == "LOW":
            return "BLOCK", "LOW_TRUST"
        if trust == "MEDIUM":
            return "REVIEW", "MEDIUM_TRUST"

        return "ALLOW", "HIGH_TRUST"

    def evaluate(self, snapshot: dict[str, Any]) -> DecisionResult:
        loss = float(snapshot.get("loss"))
        distortion = float(snapshot.get("distortion"))
        drift = float(snapshot.get("drift"))

        signals = snapshot.get("signals", {}) or {}

        structural_risk = self._compute_structural_risk(signals)
        structural_gate = structural_risk >= self.structural_gate_threshold

        # IMPORTANT: use multiplicative degradation (more stable than subtraction)
        drift_effective = max(0.0, drift * (1.0 - (self.structural_drift_scale * structural_risk)))

        score, base, penalty, gated = calculate_score(
            loss,
            distortion,
            drift_effective,
            w_loss=self.policy.w_loss,
            w_distortion=self.policy.w_distortion,
            w_drift=self.policy.w_drift,
            floor=self.policy.floor,
            penalty_scale=self.policy.penalty_scale,
            enable_drift_gate=self.policy.enable_drift_gate,
        )

        trust = classify(score, t_high=self.policy.t_high, t_med=self.policy.t_med)
        reasons = reason_codes(loss, distortion, drift, floor=self.policy.floor)

        decision, decision_reason = self._decide(trust, gated, structural_gate, signals)

        print(self.policy.w_loss, self.policy.w_distortion, self.policy.w_drift)


        return DecisionResult(
            score=score,
            trust=trust,
            base=base,
            penalty=penalty,
            gate_triggered=gated,
            reasons=reasons,
            structural_risk=structural_risk,
            structural_gate=structural_gate,
            decision=decision,
            decision_reason=decision_reason,

            
        )