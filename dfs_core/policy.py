from dataclasses import dataclass

@dataclass(frozen=True)
class DFSPolicy:
    # weights (tuning)
    w_loss: float = 0.30
    w_distortion: float = 0.45
    w_drift: float = 0.25

    # trust boundaries
    floor: float = 0.30
    penalty_scale: float = 0.40

    # classification thresholds
    t_high: float = 0.75
    t_med: float = 0.50

    # hard governance
    enable_drift_gate: bool = True
