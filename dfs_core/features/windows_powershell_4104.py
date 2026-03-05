# dfs_core/features/windows_powershell_4104.py
from __future__ import annotations
from typing import Any, Dict, Optional, Tuple
from dfs_core.scoring import DFSInputs


def _truthy(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str) and v.strip() == "":
        return False
    return True


def _is_redacted(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    s = value.strip().lower()
    return "redacted" in s or "[redacted" in s or "missing" in s


def extract(event: Dict[str, Any], policy: Optional[Dict[str, Any]] = None) -> Tuple[DFSInputs, Dict[str, bool]]:
    script_text = (
        event.get("winlog", {})
             .get("event_data", {})
             .get("ScriptBlockText")
    )
    user = event.get("user", {}).get("name")
    host = event.get("host", {}).get("name")

    has_scriptblock = _truthy(script_text) and not _is_redacted(script_text)
    has_user        = _truthy(user) and not _is_redacted(user)
    has_host        = _truthy(host) and not _is_redacted(host)

    # Signal markers
    script_s = (script_text or "").lower()
    looks_amsi_bypass    = "amsiutils" in script_s or "amsi" in script_s
    looks_download_cradle = "downloadstring" in script_s or "webclient" in script_s or "iex" in script_s
    looks_reflection      = "gettype" in script_s or "assembly" in script_s or "[ref]" in script_s
    looks_encoded         = "-encodedcommand" in script_s or "-enc " in script_s
    looks_obfuscated      = script_s.count("`") > 3 or "char(" in script_s

    # T: telemetry completeness
    telemetry = [has_scriptblock, has_user, has_host]
    t = sum(1.0 for x in telemetry if x) / float(len(telemetry))

    # S: signal clarity — scriptblock is king
    s = 0.85 if has_scriptblock else 0.20
    if has_scriptblock and (looks_amsi_bypass or looks_download_cradle or looks_reflection):
        s = min(1.0, s + 0.10)

    # B: behavioral coherence
    b = 0.50
    if has_user:  b += 0.20
    if has_host:  b += 0.15
    b = max(0.0, min(1.0, b))

    flags = {
        "has_scriptblock":        has_scriptblock,
        "has_user":               has_user,
        "has_host":               has_host,
        "has_command_line":       has_scriptblock,
        "has_parent_process":     True,
        "has_process_path":       True,
        "looks_amsi_bypass":      looks_amsi_bypass,
        "looks_download_cradle":  looks_download_cradle,
        "looks_reflection":       looks_reflection,
        "looks_encoded":          looks_encoded,
        "looks_obfuscated":       looks_obfuscated,
    }

    return DFSInputs(float(s), float(t), float(b)), flags
