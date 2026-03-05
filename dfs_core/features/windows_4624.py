# dfs_core/features/windows_4624.py
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
    host       = event.get("host", {}).get("name")
    user_name  = event.get("user", {}).get("name")
    src_ip     = event.get("source", {}).get("ip")
    logon_type = event.get("winlog", {}).get("event_data", {}).get("LogonType")
    workstation = event.get("winlog", {}).get("event_data", {}).get("WorkstationName")
    auth_pkg   = event.get("winlog", {}).get("event_data", {}).get("AuthenticationPackageName")
    process    = event.get("process", {}).get("executable")

    has_host        = _truthy(host) and not _is_redacted(host)
    has_user        = _truthy(user_name) and not _is_redacted(user_name)
    has_source_ip   = _truthy(src_ip) and not _is_redacted(src_ip)
    has_logon_type  = _truthy(logon_type) and not _is_redacted(logon_type)
    has_workstation = _truthy(workstation) and not _is_redacted(workstation)
    has_auth_pkg    = _truthy(auth_pkg) and not _is_redacted(auth_pkg)
    has_process     = _truthy(process) and not _is_redacted(process)

    telemetry = [has_host, has_user, has_source_ip, has_logon_type, has_workstation, has_auth_pkg, has_process]
    t = sum(1.0 for x in telemetry if x) / float(len(telemetry))

    s = 0.60
    if has_logon_type:  s += 0.15
    if has_source_ip:   s += 0.15
    if has_auth_pkg:    s += 0.10
    s = max(0.0, min(1.0, float(s)))

    b = 0.50
    if has_user:        b += 0.20
    if has_workstation: b += 0.15
    if has_process:     b += 0.10
    b = max(0.0, min(1.0, float(b)))

    flags = {
        "has_host":           has_host,
        "has_user":           has_user,
        "has_source_ip":      has_source_ip,
        "has_logon_type":     has_logon_type,
        "has_workstation":    has_workstation,
        "has_auth_pkg":       has_auth_pkg,
        "has_process_path":   has_process,
        "has_command_line":   True,
        "has_parent_process": True,
    }

    return DFSInputs(float(s), float(t), float(b)), flags
