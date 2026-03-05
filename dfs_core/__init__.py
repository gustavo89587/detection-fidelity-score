from .guardrails import DFSGuardrail, DFSAction
from .scoring import calculate_score, classify, clamp01, DFSInputs


class DFSModel:
    def score(self, inputs) -> float:
        if isinstance(inputs, tuple):
            s, t, b = inputs
        elif hasattr(inputs, 'signal'):
            s, t, b = inputs.signal, inputs.trust, inputs.overlap
        elif hasattr(inputs, 's'):
            s, t, b = inputs.s, inputs.t, inputs.b
        else:
            raise ValueError(f"Cannot extract s/t/b from {type(inputs)}")
        return round(float(s) * float(t) * float(b), 4)

    def interpret(self, score: float) -> str:
        if score >= 0.70:
            return "High Trust"
        if score >= 0.40:
            return "Operational"
        return "Fragile"
