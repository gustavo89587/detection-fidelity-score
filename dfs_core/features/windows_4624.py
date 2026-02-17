# dfs_core/features/windows_4624.py
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


# High-risk signals (tight, not huge lists)
PRIV_GROUP_HINTS = (
    "domain admins",
    "enterprise admins",
    "administrators",
    "account operators",
    "backup operators",
)
PRIV_USER_HINTS = ("admin", "administrator", "root", "svc_admin", "da_", "ea_")

# 4624 logon types of interest
LOGON_NETWORK = 3
LOGON_RDP = 10
LOGON_SERVICE = 5
LOGON_BATCH = 4
LOGON_UNLOCK = 7
LOGON_INTERACTIVE = 2


@dataclass(frozen=True)
class Win4624Context:
    has_user: bool
    has_domain: bool
    has_logon_type: bool
    has_source_ip: bool
    has_workstation: bool
    has_process: bool
    has_auth_package: bool
    has_elevation: bool
    has_target_sid: bool
    is_privileged_target: bool
    is_rdp: bool
    is_network: bool
    is_service_or_batch: bool


def extract_4624(event: Dict[str, Any]) -> Win4624Context:
    # ECS-ish
    user = _get(event, "user.name") or _get(event, "winlog.event_data.TargetUserName")
    domain = _get(event, "user.domain") or _get(event, "winlog.event_data.TargetDomainName")
    logon_type = _get(event, "winlog.event_data.LogonType")
    src_ip = _get(event, "source.ip") or _get(event, "winlog.event_data.IpAddress")
    workstation = _get(event, "winlog.event_data.WorkstationName") or _get(event, "source.domain")
    proc = _get(event, "process.executable") or _get(event, "winlog.event_data.ProcessName")
    auth_pkg = _get(event, "winlog.event_data.AuthenticationPackageName")
    elevation = _get(event, "winlog.event_data.ElevatedToken") or _get(event, "winlog.event_data.TokenElevationType")
    sid = _get(event, "winlog.event_data.TargetUserSid")

    has_user = _truthy(user) and not _is_redacted(user)
    has_domain = _truthy(domain) and not _is_redacted(domain)
    has_logon_type = _truthy(logon_type) and not _is_redacted(logon_type)
    has_source_ip = _truthy(src_ip) and not _is_redacted(src_ip)
    has_workstation = _truthy(workstation) and not _is_redacted(workstation)
    has_process = _truthy(proc) and not _is_redacted(proc)
    has_auth_package = _truthy(auth_pkg) and not _is_redacted(auth_pkg)
    has_elevation = _truthy(elevation) and not _is_redacted(elevation)
    has_target_sid = _truthy(sid) and not _is_redacted(sid)

    # Parse logon type as int when possible
    lt = None
    try:
        lt = int(logon_type)
    except Exception:
        lt = None

    is_rdp = (lt == LOGON_RDP)
    is_network = (lt == LOGON_NETWORK)
    is_service_or_batch = (lt in (LOGON_SERVICE, LOGON_BATCH))

    # Privileged target heuristic (kept conservative)
    u = (str(user).lower() if user is not None else "")
    d = (str(domain).lower() if domain is not None else "")
    is_priv_user = any(h in u for h in PRIV_USER_HINTS)
    # Group membership isn't directly in 4624; we approximate by name hints only for now
    is_privileged_target = is_priv_user or (u in ("administrator",))

    return Win4624Context(
        has_user=has_user,
        has_domain=has_domain,
        has_logon_type=has_logon_type,
        has_source_ip=has_source_ip,
        has_workstation=has_workstation,
        has_process=has_process,
        has_auth_package=has_auth_package,
        has_elevation=has_elevation,
        has_target_sid=has_target_sid,
        is_privileged_target=is_privileged_target,
        is_rdp=is_rdp,
        is_network=is_network,
        is_service_or_batch=is_service_or_batch,
    )


def win4624_to_inputs_and_flags(event: Dict[str, Any]) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    DFS mapping:
      - T: completeness of identity + source context (user/domain/ip/workstation/logon_type/auth_pkg/process)
      - S: clarity for decision (logon type + source ip + workstation)
      - B: coherence (privileged target + logon type indicates higher risk surface)
    """
    ctx = extract_4624(event)

    telemetry_fields = [
        ctx.has_user,
        ctx.has_domain,
        ctx.has_logon_type,
        ctx.has_source_ip,
        ctx.has_workstation,
        ctx.has_auth_package,
        ctx.has_process,
    ]
    t = sum(1.0 for x in telemetry_fields if x) / float(len(telemetry_fields))

    # Signal clarity: if we don't know source IP/workstation/logon type, decision confidence collapses.
    s = 0.55
    if ctx.has_logon_type:
        s += 0.10
    if ctx.has_source_ip:
        s += 0.20
    if ctx.has_workstation:
        s += 0.15
    s = max(0.0, min(1.0, float(s)))

    # Behavioral coherence: privileged + remote logon types increase decision relevance
    b = 0.40
    if ctx.is_privileged_target:
        b += 0.25
    if ctx.is_rdp:
        b += 0.15
    elif ctx.is_network:
        b += 0.10
    if ctx.is_service_or_batch:
        # service/batch often noisy; keep it from inflating confidence
        b -= 0.05
    b = max(0.0, min(1.0, float(b)))

    # Normalize to explain_score penalties keys
    flags = {
        # reusing keys:
        "has_command_line": ctx.has_source_ip,      # here: source ip is the "intent visibility" anchor for logon
        "has_parent_process": ctx.has_workstation,  # here: workstation is a critical chain/context anchor
        "has_user": ctx.has_user,
        "has_host": True,                           # host concept is usually local machine; not critical here
        "has_process_path": ctx.has_process,

        # extra flags
        "has_domain": ctx.has_domain,
        "has_logon_type": ctx.has_logon_type,
        "has_source_ip": ctx.has_source_ip,
        "has_auth_package": ctx.has_auth_package,
        "has_workstation": ctx.has_workstation,
        "has_elevation": ctx.has_elevation,
        "has_target_sid": ctx.has_target_sid,
        "is_privileged_target": ctx.is_privileged_target,
        "is_rdp": ctx.is_rdp,
        "is_network": ctx.is_network,
        "is_service_or_batch": ctx.is_service_or_batch,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


register("windows-4624", win4624_to_inputs_and_flags)
register("4624", win4624_to_inputs_and_flags)
register("win4624", win4624_to_inputs_and_flags)
