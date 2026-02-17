# dfs_core/policy.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
import json

from dfs_core.explain import DFSWeights, DFSPenalties
from dfs_core.guardrails import GuardrailThresholds


@dataclass(frozen=True)
class DFSPolicy:
    name: str
    weights: DFSWeights
    penalties: DFSPenalties
    thresholds: GuardrailThresholds

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "DFSPolicy":
        name = str(d.get("name", "default"))

        w = d.get("weights", {}) or {}
        p = d.get("penalties", {}) or {}
        t = d.get("thresholds", {}) or {}

        weights = DFSWeights(
            s=float(w.get("s", 0.40)),
            t=float(w.get("t", 0.35)),
            b=float(w.get("b", 0.25)),
        )

        penalties = DFSPenalties(
            missing_command_line=float(p.get("missing_command_line", 0.25)),
            missing_parent=float(p.get("missing_parent", 0.20)),
            missing_user=float(p.get("missing_user", 0.10)),
            missing_host=float(p.get("missing_host", 0.05)),
            missing_process_path=float(p.get("missing_process_path", 0.05)),
        )

        thresholds = GuardrailThresholds(
            investigate_max=float(t.get("investigate_max", 0.55)),
            escalate_max=float(t.get("escalate_max", 0.75)),
            automate_hard_min=float(t.get("automate_hard_min", 0.88)),
        )

        return DFSPolicy(name=name, weights=weights, penalties=penalties, thresholds=thresholds)


def load_policy(path: str | Path) -> DFSPolicy:
    """
    Loads:
      - .yaml / .yml (requires PyYAML)
      - .json (stdlib)

    If YAML isn't available, raise a clear message.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {p}")

    suffix = p.suffix.lower()

    if suffix in (".json",):
        data = json.loads(p.read_text(encoding="utf-8"))
        return DFSPolicy.from_dict(data)

    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "YAML policy requested but PyYAML is not installed. "
                "Install with: py -m pip install pyyaml  (or use a .json policy)."
            ) from e

        data = yaml.safe_load(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Policy YAML must be a mapping/object at the root.")
        return DFSPolicy.from_dict(data)

    raise ValueError(f"Unsupported policy type: {suffix} (use .json or .yaml/.yml)")
