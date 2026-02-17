# dfs_core/features/windows_sysmon_1.py
from __future__ import annotations

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


def _get(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _is_redacted(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    s = value.strip().lower()
    return "redacted" in s or "[redacted" in s or "missing" in s


@dataclass(frozen=True)
class Sysmon1Context:
    has_command_line: bool
    has_parent_image: bool
    has_parent_command_line: bool
    has_user: bool
    has_process_image: bool
    has_hashes: bool
    has_integrity_level: bool
    has_logon_id: bool
    host_present: bool
    looks_encoded_ps: bool
    suspicious_parent_chain: bool


def extract_sysmon1_context(event: Dict[str, Any]) -> Sysmon1Context:
    """
    Accepts either ECS-like Sysmon mapping OR raw-ish event_data style.
    We intentionally keep field access flexible.
    """

    # Common ECS-ish mappings
    cmd = _get(event, "process.command_line") or _get(event, "winlog.event_data.CommandLine")
    image = _get(event, "process.executable") or _get(event, "winlog.event_data.Image")
    parent_image = _get(event, "process.parent.executable") or _get(event, "winlog.event_data.ParentImage")
    parent_cmd = _get(event, "process.parent.command_line") or _get(event, "winlog.event_data.ParentCommandLine")

    user = _get(event, "user.name") or _get(event, "winlog.event_data.User")
    host = _get(event, "host.name") or _get(event, "winlog.computer_name")

    hashes = _get(event, "winlog.event_data.Hashes") or _get(event, "process.hash.sha256") or _get(event, "process.hash.md5")
    integrity = _get(event, "winlog.event_data.IntegrityLevel") or _get(event, "process.integrity_level")
    logon_id = _get(event, "winlog.event_data.LogonId")

    has_command_line = _truthy(cmd) and not _is_redacted(cmd)
    has_process_image = _truthy(image) and not _is_redacted(image)
    has_parent_image = _truthy(parent_image) and not _is_redacted(parent_image)
    has_parent_command_line = _truthy(parent_cmd) and not _is_redacted(parent_cmd)
    has_user = _truthy(user) and not _is_redacted(user)
    host_present = _truthy(host) and not _is_redacted(host)

    has_hashes = _truthy(hashes) and not _is_redacted(hashes)
    has_integrity_level = _truthy(integrity) and not _is_redacted(integrity)
    has_logon_id = _truthy(logon_id) and not _is_redacted(logon_id)

    cmd_s = (cmd or "")
    looks_encoded_ps = isinstance(cmd_s, str) and (" -enc " in cmd_s.lower() or " -encodedcommand" in cmd_s.lower())

    parent_s = (parent_image or "")
    image_s = (image or "")
    suspicious_parent_chain = (
        isinstance(parent_s, str)
        and isinstance(image_s, str)
        and ("winword.exe" in parent_s.lower() or "excel.exe" in parent_s.lower() or "outlook.exe" in parent_s.lower())
        and ("powershell.exe" in image_s.lower() or "cmd.exe" in image_s.lower() or "wscript.exe" in image_s.lower())
    )

    return Sysmon1Context(
        has_command_line=has_command_line,
        has_parent_image=has_parent_image,
        has_parent_command_line=has_parent_command_line,
        has_user=has_user,
        has_process_image=has_process_image,
        has_hashes=has_hashes,
        has_integrity_level=has_integrity_level,
        has_logon_id=has_logon_id,
        host_present=host_present,
        looks_encoded_ps=looks_encoded_ps,
        suspicious_parent_chain=suspicious_parent_chain,
    )


def sysmon1_to_inputs_and_flags(event: Dict[str, Any]) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    DFS mapping:
      T: completeness of high-value Sysmon fields
      S: intent visibility (command_line) + intent markers
      B: coherence (parent chain + user + logon/integrity)
    """
    ctx = extract_sysmon1_context(event)

    telemetry_fields = [
        ctx.host_present,
        ctx.has_process_image,
        ctx.has_command_line,
        ctx.has_parent_image,
        ctx.has_parent_command_line,
        ctx.has_user,
        ctx.has_hashes,
        ctx.has_integrity_level,
        ctx.has_logon_id,
    ]
    t = sum(1.0 for x in telemetry_fields if x) / float(len(telemetry_fields))

    # Signal clarity: Sysmon is often used exactly for command-line intent.
    s = 0.90 if ctx.has_command_line else 0.30
    if ctx.looks_encoded_ps and ctx.has_command_line:
        s = min(1.0, s + 0.08)

    # Behavioral coherence
    b = 0.45
    if ctx.has_parent_image:
        b += 0.18
    if ctx.has_parent_command_line:
        b += 0.07
    if ctx.has_user:
        b += 0.15
    if ctx.has_logon_id:
        b += 0.08
    if ctx.has_integrity_level:
        b += 0.05
    if ctx.suspicious_parent_chain:
        b += 0.02
    b = max(0.0, min(1.0, b))

    # Flags normalized for explain_score
    flags = {
        "has_command_line": ctx.has_command_line,
        "has_parent_process": ctx.has_parent_image,
        "has_user": ctx.has_user,
        "has_host": ctx.host_present,
        "has_process_path": ctx.has_process_image,
        # extra insight flags (optional)
        "has_hashes": ctx.has_hashes,
        "has_integrity_level": ctx.has_integrity_level,
        "has_logon_id": ctx.has_logon_id,
        "has_parent_command_line": ctx.has_parent_command_line,
        "looks_encoded_ps": ctx.looks_encoded_ps,
        "suspicious_parent_chain": ctx.suspicious_parent_chain,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


# Register kinds
register("windows-sysmon-1", sysmon1_to_inputs_and_flags)
register("sysmon-1", sysmon1_to_inputs_and_flags)
register("1", sysmon1_to_inputs_and_flags)
