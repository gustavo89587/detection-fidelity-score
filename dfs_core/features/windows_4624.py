from __future__ import annotations

from typing import Any, Dict, Optional

from core.model import DFSInputs


def extract(event: Dict[str, Any], policy: Optional[Dict[str, Any]] = None) -> DFSInputs:
    # Bootstrap heurístico: só pra destravar o CLI
    script_text = (
        event.get("winlog", {})
        .get("event_data", {})
        .get("ScriptBlockText")
    )

    has_script = 1.0 if script_text else 0.0

    # placeholders estáveis
    signal = 0.7 + (0.2 * has_script)  # 0.7..0.9
    overlap = 0.5
    trust = 0.7

    return DFSInputs(signal, overlap, trust)
