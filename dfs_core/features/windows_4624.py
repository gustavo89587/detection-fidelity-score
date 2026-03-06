# dfs_core/features/windows_4624.py
"""
Windows Security Event 4624 — An account was successfully logged on.

DFS Mapping Philosophy:
  S (Signal Clarity):   How explicit is the intent of this logon?
                        High-risk logon types + lateral movement indicators drive S up.
  T (Telemetry):        How complete is the forensic context?
                        Missing source IP on a remote logon is a hard degradation.
  B (Behavioral):       How coherent is the causal chain?
                        Identity + auth package + workstation + process = full picture.

Detection-relevant logon types:
  2  = Interactive (console)         — low risk baseline
  3  = Network                       — common, watch for anonymous
  4  = Batch                         — service accounts
  5  = Service                       — service accounts
  7  = Unlock                        — low signal
  8  = NetworkCleartext              — HIGH RISK: credentials in cleartext
  9  = NewCredentials (runas /netonly) — lateral movement indicator
  10 = RemoteInteractive (RDP)       — HIGH RISK: remote access
  11 = CachedInteractive             — offline / disconnected
  12 = CachedRemoteInteractive       — cached RDP
  13 = CachedUnlock                  — low signal

Auth packages:
  NTLM      — legacy, high-risk in modern AD environments
  Kerberos  — expected in healthy AD
  Negotiate — typically resolves to Kerberos (good)
  CredSSP   — RDP with NLA (expected for type 10)
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from dfs_core.scoring import DFSInputs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(d: Dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


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
    return (
        "redacted" in s
        or "[redacted" in s
        or "missing" in s
        or s in ("-", "null", "none", "n/a", "unknown")
    )


def _clean(v: Any) -> Optional[str]:
    """Return string if truthy and not redacted, else None."""
    if not _truthy(v):
        return None
    if _is_redacted(str(v)):
        return None
    return str(v)


# ---------------------------------------------------------------------------
# Logon type risk classification
# ---------------------------------------------------------------------------

# Risk tiers for logon types (0.0 = noise, 1.0 = maximum risk)
_LOGON_TYPE_RISK: Dict[str, float] = {
    "2":  0.20,   # Interactive — console, low baseline
    "3":  0.35,   # Network — common service traffic
    "4":  0.15,   # Batch — scheduled tasks
    "5":  0.15,   # Service — service startup
    "7":  0.10,   # Unlock — screen unlock
    "8":  0.90,   # NetworkCleartext — credentials in cleartext (critical)
    "9":  0.80,   # NewCredentials — runas /netonly, classic lateral movement setup
    "10": 0.85,   # RemoteInteractive — RDP, high value target
    "11": 0.25,   # CachedInteractive — offline logon
    "12": 0.40,   # CachedRemoteInteractive — cached RDP
    "13": 0.10,   # CachedUnlock — low signal
}

# Logon types where source IP is forensically mandatory
_REMOTE_LOGON_TYPES = {"3", "8", "9", "10", "12"}

# Auth packages that elevate risk in modern AD environments
_RISKY_AUTH_PACKAGES = {"ntlm", "msv1_0"}
_EXPECTED_AUTH_PACKAGES = {"kerberos", "negotiate", "credssp"}


# ---------------------------------------------------------------------------
# Context extraction
# ---------------------------------------------------------------------------

def _extract_context(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pull all 4624-relevant fields from ECS-like or raw winlog structure.
    Returns a flat context dict for scoring.
    """
    ed = _get(event, "winlog.event_data") or {}

    host        = _clean(_get(event, "host.name"))
    user_name   = _clean(_get(event, "user.name") or ed.get("TargetUserName"))
    user_domain = _clean(_get(event, "user.domain") or ed.get("TargetDomainName"))
    src_ip      = _clean(_get(event, "source.ip") or ed.get("IpAddress"))
    src_port    = _clean(_get(event, "source.port") or ed.get("IpPort"))
    process     = _clean(_get(event, "process.executable") or ed.get("ProcessName"))

    logon_type      = _clean(ed.get("LogonType"))
    workstation     = _clean(ed.get("WorkstationName"))
    auth_pkg        = _clean(ed.get("AuthenticationPackageName"))
    lm_pkg          = _clean(ed.get("LmPackageName"))
    logon_process   = _clean(ed.get("LogonProcessName"))
    subject_user    = _clean(ed.get("SubjectUserName"))
    subject_domain  = _clean(ed.get("SubjectDomainName"))
    logon_id        = _clean(ed.get("TargetLogonId"))
    impersonation   = _clean(ed.get("ImpersonationLevel"))
    elevated        = _clean(ed.get("ElevatedToken"))

    return {
        "host":             host,
        "user_name":        user_name,
        "user_domain":      user_domain,
        "src_ip":           src_ip,
        "src_port":         src_port,
        "process":          process,
        "logon_type":       logon_type,
        "workstation":      workstation,
        "auth_pkg":         auth_pkg,
        "lm_pkg":           lm_pkg,
        "logon_process":    logon_process,
        "subject_user":     subject_user,
        "subject_domain":   subject_domain,
        "logon_id":         logon_id,
        "impersonation":    impersonation,
        "elevated":         elevated,
    }


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps Windows 4624 event → (DFSInputs, flags).

    Score interpretation:
      High DFS (>0.70): RDP/Network logon with full forensic context + elevated risk signals
      Mid  DFS (0.40–0.70): Standard logon with decent telemetry
      Low  DFS (<0.40): Missing critical context or low-risk logon type
    """
    ctx = _extract_context(event)

    logon_type   = ctx["logon_type"] or "2"
    auth_pkg_raw = (ctx["auth_pkg"] or "").lower().strip()
    is_remote    = logon_type in _REMOTE_LOGON_TYPES
    logon_risk   = _LOGON_TYPE_RISK.get(logon_type, 0.30)

    # Presence flags
    has_host          = ctx["host"] is not None
    has_user          = ctx["user_name"] is not None
    has_user_domain   = ctx["user_domain"] is not None
    has_source_ip     = ctx["src_ip"] is not None
    has_logon_type    = ctx["logon_type"] is not None
    has_workstation   = ctx["workstation"] is not None
    has_auth_pkg      = ctx["auth_pkg"] is not None
    has_process       = ctx["process"] is not None
    has_logon_id      = ctx["logon_id"] is not None
    has_subject       = ctx["subject_user"] is not None
    has_impersonation = ctx["impersonation"] is not None
    has_elevated      = ctx["elevated"] is not None

    # Risk signals
    is_ntlm           = auth_pkg_raw in _RISKY_AUTH_PACKAGES
    is_cleartext      = logon_type == "8"
    is_rdp            = logon_type == "10"
    is_new_creds      = logon_type == "9"  # runas /netonly
    is_network        = logon_type == "3"
    is_anonymous      = (ctx["user_name"] or "").lower() in ("anonymous logon", "anonymous")
    is_machine_acct   = (ctx["user_name"] or "").endswith("$")
    is_elevated_token = ctx["elevated"] == "%%1842"  # TokenElevationTypeFull
    missing_src_on_remote = is_remote and not has_source_ip

    # -----------------------------------------------------------------------
    # T — Telemetry Completeness
    # Weight remote-critical fields higher when logon is remote
    # -----------------------------------------------------------------------
    base_fields = [
        has_host, has_user, has_logon_type, has_auth_pkg, has_process,
    ]
    remote_fields = [has_source_ip, has_workstation, has_logon_id] if is_remote else [has_workstation, has_logon_id]
    enrichment_fields = [has_user_domain, has_subject, has_impersonation, has_elevated]

    # Weighted average: base=0.50, remote=0.35 (if remote), enrichment=0.15
    base_score_t   = sum(1.0 for x in base_fields if x) / max(len(base_fields), 1)
    remote_score_t = sum(1.0 for x in remote_fields if x) / max(len(remote_fields), 1) if remote_fields else 1.0
    enrich_score_t = sum(1.0 for x in enrichment_fields if x) / max(len(enrichment_fields), 1)

    if is_remote:
        t = (base_score_t * 0.50) + (remote_score_t * 0.35) + (enrich_score_t * 0.15)
    else:
        t = (base_score_t * 0.65) + (enrich_score_t * 0.35)

    # Hard penalty: missing source IP on remote logon = major telemetry gap
    if missing_src_on_remote:
        t = min(t, 0.45)

    # -----------------------------------------------------------------------
    # S — Signal Clarity (how much does this logon tell us about intent?)
    # -----------------------------------------------------------------------
    s = logon_risk  # Start with logon type risk as baseline

    # Auth package modifiers
    if is_ntlm and is_remote:
        s = min(1.0, s + 0.10)  # NTLM on remote logon = elevated concern
    if is_cleartext:
        s = min(1.0, s + 0.05)  # Already captured in logon type, small boost

    # Completeness of identity signal
    if has_user and has_user_domain:
        s = min(1.0, s + 0.05)
    if has_auth_pkg:
        s = min(1.0, s + 0.03)

    # Anonymous logon is high signal (explicit attack indicator)
    if is_anonymous:
        s = min(1.0, s + 0.15)

    # Elevated token = privilege escalation context
    if is_elevated_token:
        s = min(1.0, s + 0.10)

    s = max(0.0, min(1.0, float(s)))

    # -----------------------------------------------------------------------
    # B — Behavioral Coherence (causal chain completeness)
    # -----------------------------------------------------------------------
    b = 0.40  # baseline

    if has_user:            b += 0.15
    if has_host:            b += 0.10
    if has_workstation:     b += 0.10
    if has_subject:         b += 0.08  # who initiated the logon
    if has_logon_id:        b += 0.07  # tracks session lifecycle
    if has_process:         b += 0.05  # which process created the logon
    if has_impersonation:   b += 0.05  # impersonation level adds context

    # NTLM on remote logon breaks expected Kerberos chain
    if is_ntlm and is_remote:
        b = max(0.0, b - 0.10)

    # New credentials (runas /netonly) — no local auth change, suspicious
    if is_new_creds:
        b = max(0.0, b - 0.05)

    b = max(0.0, min(1.0, float(b)))

    # -----------------------------------------------------------------------
    # Flags (normalized for explain_score + pipeline penalties)
    # -----------------------------------------------------------------------
    flags = {
        # Standard DFS flags
        "has_host":             has_host,
        "has_user":             has_user,
        "has_source_ip":        has_source_ip,
        "has_process_path":     has_process,
        "has_parent_process":   True,       # N/A for logon events
        "has_command_line":     True,       # N/A for logon events
        # 4624-specific flags
        "has_logon_type":       has_logon_type,
        "has_workstation":      has_workstation,
        "has_auth_pkg":         has_auth_pkg,
        "has_logon_id":         has_logon_id,
        "has_user_domain":      has_user_domain,
        "has_subject":          has_subject,
        "has_impersonation":    has_impersonation,
        "has_elevated":         has_elevated,
        # Risk signal flags
        "is_remote_logon":      is_remote,
        "is_rdp":               is_rdp,
        "is_ntlm":              is_ntlm,
        "is_cleartext":         is_cleartext,
        "is_new_credentials":   is_new_creds,
        "is_anonymous":         is_anonymous,
        "is_machine_account":   is_machine_acct,
        "is_elevated_token":    is_elevated_token,
        "missing_src_on_remote": missing_src_on_remote,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


def win4624_to_inputs_and_flags(event: Dict[str, Any]) -> Tuple[DFSInputs, Dict[str, bool]]:
    """Alias for registry compatibility."""
    return extract(event)
