# dfs_core/features/windows_powershell_4104.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from dfs_core.scoring import DFSInputs
from dfs_core.features.registry import register


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


def _get(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


# -----------------------------
# Heuristics (high-signal focus)
# -----------------------------

# Classic download cradle / execution patterns
RE_DOWNLOAD_CRADLE = re.compile(
    r"(iwr|invoke-webrequest|wget|curl|new-object\s+net\.webclient|downloadstring|downloadfile|bitsadmin)",
    re.IGNORECASE,
)

RE_ENCODED_COMMAND = re.compile(r"(-enc\b|-encodedcommand\b)", re.IGNORECASE)

# AMSI bypass / reflection "gold"
RE_AMSI = re.compile(r"(amsi|amsiutils|amsiscanbuffer)", re.IGNORECASE)
RE_REFLECTION = re.compile(r"(reflection\.assembly|assembly\.load|gettype\(|getmethod\(|invoke\()", re.IGNORECASE)

# Obfuscation hints (conservative)
RE_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b")  # long base64-like
RE_STRING_SPLIT = re.compile(r"('|\")\s*\+\s*('|\")")  # lots of string concat
RE_CHAR_CODE = re.compile(r"\[char\]\s*\d{2,3}", re.IGNORECASE)
RE_FROMBASE64 = re.compile(r"frombase64string", re.IGNORECASE)

# A small "suspicious verbs" list (keep tight)
RE_SUS_VERBS = re.compile(
    r"(invoke-expression|iex\b|start-process|add-mppreference|set-mppreference|reg\s+add|rundll32|mshta)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PS4104Context:
    has_scriptblock: bool
    has_user: bool
    has_host: bool
    has_event_id: bool
    looks_encoded: bool
    looks_download_cradle: bool
    looks_amsi_bypass: bool
    looks_reflection: bool
    looks_obfuscated: bool
    script_len: int


def extract_ps4104_context(event: Dict[str, Any]) -> Tuple[PS4104Context, str]:
    """
    Accept flexible shapes:
      - winlog.event_data.ScriptBlockText (common)
      - powershell.script_block_text (custom)
    """
    text = (
        _get(event, "winlog.event_data.ScriptBlockText")
        or _get(event, "powershell.script_block_text")
        or _get(event, "event.original")  # sometimes raw
    )

    user = _get(event, "user.name") or _get(event, "winlog.event_data.User")
    host = _get(event, "host.name") or _get(event, "winlog.computer_name")
    event_id = _get(event, "event.code") or _get(event, "winlog.event_id")

    has_scriptblock = _truthy(text) and not _is_redacted(text)
    has_user = _truthy(user) and not _is_redacted(user)
    has_host = _truthy(host) and not _is_redacted(host)
    has_event_id = _truthy(event_id)

    sb = text if isinstance(text, str) else ""
    sb_low = sb.lower()

    looks_encoded = bool(RE_ENCODED_COMMAND.search(sb)) or bool(RE_BASE64_BLOB.search(sb))
    looks_download = bool(RE_DOWNLOAD_CRADLE.search(sb))
    looks_amsi = bool(RE_AMSI.search(sb))
    looks_refl = bool(RE_REFLECTION.search(sb))

    # Obfuscation heuristics:
    # - long base64 blob
    # - heavy string concat
    # - [char] codes
    # - FromBase64String
    # - excessive backticks often used in PS obfuscation
    backticks = sb.count("`")
    looks_obf = (
        bool(RE_BASE64_BLOB.search(sb))
        or bool(RE_STRING_SPLIT.search(sb))
        or bool(RE_CHAR_CODE.search(sb))
        or bool(RE_FROMBASE64.search(sb))
        or backticks >= 10
    )

    ctx = PS4104Context(
        has_scriptblock=has_scriptblock,
        has_user=has_user,
        has_host=has_host,
        has_event_id=has_event_id,
        looks_encoded=looks_encoded,
        looks_download_cradle=looks_download,
        looks_amsi_bypass=looks_amsi,
        looks_reflection=looks_refl,
        looks_obfuscated=looks_obf,
        script_len=len(sb),
    )
    return ctx, sb


def ps4104_to_inputs_and_flags(event: Dict[str, Any]) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    DFS mapping (4104):
      - S: signal clarity is the script content itself (but obfuscation reduces clarity)
      - T: telemetry completeness (has scriptblock + user + host + event_id)
      - B: behavioral coherence (presence of high-risk technique markers)
    """
    ctx, sb = extract_ps4104_context(event)

    # Telemetry completeness: 4104 is valuable if text exists.
    telemetry_fields = [
        ctx.has_scriptblock,
        ctx.has_user,
        ctx.has_host,
        ctx.has_event_id,
    ]
    t = sum(1.0 for x in telemetry_fields if x) / float(len(telemetry_fields))

    # Signal clarity (S):
    # If scriptblock is missing, clarity collapses.
    if not ctx.has_scriptblock:
        s = 0.20
    else:
        s = 0.85
        # obfuscation reduces clarity (even if malicious, decision confidence drops)
        if ctx.looks_obfuscated:
            s -= 0.20
        # encoded indicators reduce clarity for immediate action
        if ctx.looks_encoded:
            s -= 0.10
        # clamp
        s = max(0.0, min(1.0, float(s)))

    # Behavioral coherence (B):
    # "Gold" techniques raise behavior confidence, even if obfuscated.
    b = 0.45
    if ctx.looks_download_cradle:
        b += 0.10
    if ctx.looks_amsi_bypass:
        b += 0.25
    if ctx.looks_reflection:
        b += 0.15

    # Some extra suspicious verbs add a bit
    if ctx.has_scriptblock and RE_SUS_VERBS.search(sb or ""):
        b += 0.05

    b = max(0.0, min(1.0, float(b)))

    # For explain_score penalties keys:
    # we reuse has_command_line as "has_scriptblock_text" conceptually.
    flags = {
        "has_command_line": ctx.has_scriptblock,   # reusing existing penalty slot
        "has_parent_process": True,                # N/A for 4104
        "has_user": ctx.has_user,
        "has_host": ctx.has_host,
        "has_process_path": True,                  # N/A for 4104
        # extra visibility
        "has_scriptblock": ctx.has_scriptblock,
        "looks_encoded": ctx.looks_encoded,
        "looks_download_cradle": ctx.looks_download_cradle,
        "looks_amsi_bypass": ctx.looks_amsi_bypass,
        "looks_reflection": ctx.looks_reflection,
        "looks_obfuscated": ctx.looks_obfuscated,
        "script_len": ctx.script_len,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


# Register kinds
register("windows-powershell-4104", ps4104_to_inputs_and_flags)
register("powershell-4104", ps4104_to_inputs_and_flags)
register("4104", ps4104_to_inputs_and_flags)
