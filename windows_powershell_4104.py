# dfs_core/features/windows_powershell_4104.py
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from core.model import DFSInputs


def extract(event: Dict[str, Any], policy: Optional[Dict[str, Any]] = None) -> DFSInputs:
    """
    Minimal extractor for Windows PowerShell 4104 events.

    Contract:
    - event: dict already parsed from JSONL line
    - policy: dict loaded from policy json (optional)

    Returns:
    - DFSInputs (from core.model)
    """

    # ---------
    # Minimal heuristic (TEMPORARY): produce stable inputs just to unblock the pipeline
    # You will replace this with real feature engineering later.
    # ---------

    # Example: consider "ScriptBlockText" presence as "signal"
    script_text = (
        event.get("winlog", {})
            .get("event_data", {})
            .get("ScriptBlockText")
    )

    has_script = 1.0 if script_text else 0.0

    # Very naive placeholders
    signal = 0.7 + (0.2 * has_script)   # 0.7..0.9
    overlap = 0.5                       # noise overlap placeholder
    trust = 0.7                         # operational trust placeholder

    # IMPORTANT:
    # Adjust the constructor below to match your real DFSInputs signature.
    return DFSInputs(signal, overlap, trust)
