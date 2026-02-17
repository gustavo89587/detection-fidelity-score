# dfs_core/features/registry.py
from __future__ import annotations

from typing import Any, Callable, Dict, Tuple

from dfs_core.scoring import DFSInputs

# extractor signature:
# event(dict) -> (DFSInputs, flags_dict)
Extractor = Callable[[Dict[str, Any]], Tuple[DFSInputs, Dict[str, bool]]]

_REGISTRY: Dict[str, Extractor] = {}


def register(kind: str, extractor: Extractor) -> None:
    _REGISTRY[kind.lower().strip()] = extractor


def get(kind: str) -> Extractor:
    k = kind.lower().strip()
    if k not in _REGISTRY:
        raise KeyError(f"Extractor not registered: {kind}")
    return _REGISTRY[k]


def list_kinds():
    return sorted(_REGISTRY.keys())
