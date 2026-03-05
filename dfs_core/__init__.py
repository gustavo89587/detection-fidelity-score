from .guardrails import DFSGuardrail, DFSAction
from .scoring import calculate_score, classify, clamp01, DFSInputs


class DFSModel:
    def score(self, inputs) -> float:
        if isinstance(inputs, tuple):
            s, t, b = inputs
        else:
            s, t, b = inputs.s, inputs.t, inputs.b
        return round(s * t * b, 4)