# core/model.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Final


def _validate_unit_interval(name: str, value: float) -> float:
    if not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number in [0, 1], got type={type(value).__name__}")
    v = float(value)
    if v < 0.0 or v > 1.0:
        raise ValueError(f"{name} must be in [0, 1], got {v}")
    return v


@dataclass(frozen=True, slots=True)
class DFSInputs:
    """
    Canonical DFS inputs for scoring.

    Semântica (prática):
    - signal: quão forte/inequívoco é o sinal (0..1)
    - overlap: quanto o sinal se confunde com ruído/benigno (0..1)  -> maior = pior
    - trust: quão acionável/confiável é operacionalmente (0..1)

    Observação: overlap é "custo de ruído". No score final, ele entra invertido (1 - overlap).
    """
    signal: float
    overlap: float
    trust: float

    def __post_init__(self) -> None:
        # validações duras (para evitar lixo entrando no pipeline)
        object.__setattr__(self, "signal", _validate_unit_interval("signal", self.signal))
        object.__setattr__(self, "overlap", _validate_unit_interval("overlap", self.overlap))
        object.__setattr__(self, "trust", _validate_unit_interval("trust", self.trust))


class DFSModel:
    """
    DFS scoring model.

    Score em [0..1] com interpretação qualitativa.
    Mantido simples e estável agora (sem reestruturar repo), mas já com guardrails.
    """

    # Pesos simples e fáceis de explicar/defender em review
    W_SIGNAL: Final[float] = 0.45
    W_NOISE: Final[float] = 0.30   # entra como (1 - overlap)
    W_TRUST: Final[float] = 0.25

    def score(self, inputs: DFSInputs) -> float:
        # DFSInputs já valida 0..1, mas eu mantenho a checagem aqui também por segurança
        s = _validate_unit_interval("signal", inputs.signal)
        o = _validate_unit_interval("overlap", inputs.overlap)
        t = _validate_unit_interval("trust", inputs.trust)

        noise_component = 1.0 - o  # overlap alto => penaliza

        raw = (self.W_SIGNAL * s) + (self.W_NOISE * noise_component) + (self.W_TRUST * t)

        # clamp defensivo
        if raw < 0.0:
            return 0.0
        if raw > 1.0:
            return 1.0
        return float(raw)

    def interpret(self, score: float) -> str:
        v = _validate_unit_interval("score", score)

        # bandas simples e previsíveis (boa para SOC / governança)
        if v >= 0.85:
            return "High Trust"
        if v >= 0.65:
            return "Medium Trust"
        if v >= 0.40:
            return "Low Trust"
        return "Untrusted"
