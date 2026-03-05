# dfs_core/features/windows_4688.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


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
class Win4688Context:
    has_command_line: bool
    has_parent_process: bool
    has_user: bool
    has_process_path: bool
    has_host: bool
    looks_encoded_ps: bool
    suspicious_parent_chain: bool


def extract_win4688_context(event: Dict[str, Any]) -> Win4688Context:
    cmd = _get(event, "process.command_line") or _get(event, "winlog.event_data.CommandLine")
    proc = _get(event, "process.executable") or _get(event, "winlog.event_data.NewProcessName")
    parent = _get(event, "process.parent.executable") or _get(event, "winlog.event_data.CreatorProcessName")
    user = _get(event, "user.name")
    host = _get(event, "host.name")

    has_command_line = _truthy(cmd) and not _is_redacted(cmd)
    has_parent_process = _truthy(parent) and not _is_redacted(parent)
    has_user = _truthy(user) and not _is_redacted(user)
    has_process_path = _truthy(proc) and not _is_redacted(proc)
    has_host = _truthy(host) and not _is_redacted(host)

    cmd_s = (cmd or "")
    looks_encoded_ps = isinstance(cmd_s, str) and (
        " -enc " in cmd_s.lower() or " -encodedcommand" in cmd_s.lower()
    )

    parent_s = (parent or "")
    proc_s = (proc or "")
    suspicious_parent_chain = (
        isinstance(parent_s, str)
        and isinstance(proc_s, str)
        and (
            "winword.exe" in parent_s.lower()
            or "excel.exe" in parent_s.lower()
            or "outlook.exe" in parent_s.lower()
        )
        and ("powershell.exe" in proc_s.lower())
    )

    return Win4688Context(
        has_command_line=has_command_line,
        has_parent_process=has_parent_process,
        has_user=has_user,
        has_process_path=has_process_path,
        has_host=has_host,
        looks_encoded_ps=looks_encoded_ps,
        suspicious_parent_chain=suspicious_parent_chain,
    )


def win4688_to_dfs_inputs(event: Dict[str, Any]) -> tuple:
    ctx = extract_win4688_context(event)

    telemetry_fields = [
        ctx.has_host,
        ctx.has_process_path,
        ctx.has_user,
        ctx.has_parent_process,
        ctx.has_command_line,
    ]
    t = sum(1.0 for x in telemetry_fields if x) / float(len(telemetry_fields))

    s = 0.85 if ctx.has_command_line else 0.35
    if ctx.looks_encoded_ps and ctx.has_command_line:
        s = min(1.0, s + 0.10)

    b = 0.50
    if ctx.has_parent_process:
        b += 0.25
    if ctx.has_user:
        b += 0.15
    if ctx.suspicious_parent_chain:
        b += 0.10
    b = max(0.0, min(1.0, b))

    return (float(s), float(t), float(b))


def win4688_context_flags(event: dict) -> dict:
    ctx = extract_win4688_context(event)
    return {
        "has_command_line": ctx.has_command_line,
        "has_parent_process": ctx.has_parent_process,
        "has_user": ctx.has_user,
        "has_process_path": ctx.has_process_path,
        "has_host": ctx.has_host,
        "looks_encoded_ps": ctx.looks_encoded_ps,
        "suspicious_parent_chain": ctx.suspicious_parent_chain,
    }


def win4688_to_inputs_and_flags(event: dict):
    return win4688_to_dfs_inputs(event), win4688_context_flags(event)


from dfs_core.features.registry import register

register("windows-4688", win4688_to_inputs_and_flags)
register("4688", win4688_to_inputs_and_flags)
register("win4688", win4688_to_inputs_and_flags)