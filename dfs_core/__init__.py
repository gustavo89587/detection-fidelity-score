from .guardrails import DFSGuardrail, DFSAction
from .scoring import calculate_score, classify, clamp01, DFSInputs


class DFSModel:
    def score(self, inputs) -> float:
        if isinstance(inputs, tuple):
            s, t, b = inputs
        elif hasattr(inputs, 's'):
            s, t, b = inputs.s, inputs.t, inputs.b
        elif hasattr(inputs, 'signal'):
            s, t, b = inputs.signal, inputs.trust, inputs.overlap
        else:
            raise ValueError(f"Cannot extract s/t/b from {type(inputs)}")
        return round(s * t * b, 4)