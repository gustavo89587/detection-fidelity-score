# dfs_core/features/gcp_audit_log.py
"""
Google Cloud Audit Log → DFS Inputs

GCP Audit Log types:
  - Admin Activity  : changes to config/metadata (always enabled, free)
  - Data Access     : read/write to data (optional, paid)
  - System Event    : GCP-initiated actions
  - Policy Denied   : org policy violations

DFS Mapping:
  S (Signal Clarity):   Method risk + service sensitivity + error signals
  T (Telemetry):        Principal + resource + request + network completeness
  B (Behavioral):       Coherence of caller identity + resource context + auth chain

Key fields (Cloud Logging / AuditLog proto):
  protoPayload.methodName, serviceName, resourceName
  protoPayload.authenticationInfo (principalEmail, serviceAccountDelegationInfo)
  protoPayload.authorizationInfo (permission, granted)
  protoPayload.requestMetadata (callerIp, callerSuppliedUserAgent)
  protoPayload.status (code, message)
  resource (type, labels)
  severity, logName, receiveTimestamp
"""

from __future__ import annotations
from typing import Any, Dict, Optional, Tuple
from dfs_core.scoring import DFSInputs


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
    if isinstance(v, str) and v.strip().lower() in ("", "-", "null", "none", "unknown"):
        return False
    return True


def _clean(v: Any) -> Optional[str]:
    return str(v) if _truthy(v) else None


# High-risk GCP methods (partial match)
_HIGH_RISK_METHODS = {
    # IAM
    "setiampolicy", "createserviceaccount", "createserviceaccountkey",
    "deleteserviceaccount", "disableserviceaccount",
    "setserviceaccountiampolicy", "uploadserviceaccountkey",
    # Compute
    "insert", "setmetadata", "addaccessconfig",
    "setcommoninstancemetadata",
    # Storage
    "storage.buckets.setiampolicy", "storage.objects.setIamPolicy",
    # KMS
    "cloudkms.cryptokeys.setIamPolicy", "cryptokeys.create",
    # Org policy
    "organizations.setIamPolicy", "folders.setIamPolicy",
    # Secrets
    "addsecretversion", "accesssecretversion",
    # GKE
    "clusters.create", "clusters.delete", "nodepools.create",
}

# Sensitive GCP services
_SENSITIVE_SERVICES = {
    "iam.googleapis.com", "cloudkms.googleapis.com",
    "secretmanager.googleapis.com", "cloudresourcemanager.googleapis.com",
    "container.googleapis.com", "sqladmin.googleapis.com",
    "storage.googleapis.com", "bigquery.googleapis.com",
    "logging.googleapis.com", "monitoring.googleapis.com",
    "compute.googleapis.com",
}


def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:

    # Support both raw log entry and protoPayload-wrapped
    proto   = event.get("protoPayload") or event.get("proto_payload") or event
    res     = event.get("resource") or {}
    res_labels = res.get("labels") or {}

    # Core fields
    method      = _clean(proto.get("methodName") or proto.get("method_name"))
    service     = _clean(proto.get("serviceName") or proto.get("service_name"))
    resource_name = _clean(proto.get("resourceName") or proto.get("resource_name"))
    log_name    = _clean(event.get("logName") or event.get("log_name"))
    severity    = _clean(event.get("severity"))
    timestamp   = _clean(event.get("receiveTimestamp") or event.get("timestamp"))

    # Auth info
    auth_info   = proto.get("authenticationInfo") or proto.get("authentication_info") or {}
    principal   = _clean(auth_info.get("principalEmail") or auth_info.get("principal_email"))
    authority   = _clean(auth_info.get("authoritySelector"))
    delegation  = auth_info.get("serviceAccountDelegationInfo") or []
    is_delegated = len(delegation) > 0

    # Authorization info
    authz_info  = proto.get("authorizationInfo") or proto.get("authorization_info") or []
    if isinstance(authz_info, list) and authz_info:
        authz_first = authz_info[0] if isinstance(authz_info[0], dict) else {}
    else:
        authz_first = {}
    permission  = _clean(authz_first.get("permission"))
    authz_granted = authz_first.get("granted")

    # Request metadata
    req_meta    = proto.get("requestMetadata") or proto.get("request_metadata") or {}
    caller_ip   = _clean(req_meta.get("callerIp") or req_meta.get("caller_ip"))
    user_agent  = _clean(req_meta.get("callerSuppliedUserAgent") or req_meta.get("caller_supplied_user_agent"))

    # Status
    status      = proto.get("status") or {}
    status_code = status.get("code") or status.get("Code") or 0
    status_msg  = _clean(status.get("message") or status.get("Message"))
    is_success  = int(status_code) == 0

    # Resource context
    project_id  = _clean(res_labels.get("project_id") or _get(event, "resource.labels.project_id"))
    zone        = _clean(res_labels.get("zone"))
    cluster     = _clean(res_labels.get("cluster_name"))
    resource_type = _clean(res.get("type"))

    # Derived signals
    method_lower  = (method or "").lower()
    service_lower = (service or "").lower()

    is_high_risk_method  = any(m in method_lower for m in _HIGH_RISK_METHODS)
    is_sensitive_service = service_lower in _SENSITIVE_SERVICES
    is_service_account   = "@" in (principal or "") and "gserviceaccount" in (principal or "").lower()
    is_human_user        = "@" in (principal or "") and not is_service_account
    is_write_operation   = any(w in method_lower for w in ("create", "insert", "update", "delete", "patch", "set", "add", "upload", "disable", "enable"))
    is_read_operation    = any(r in method_lower for r in ("get", "list", "describe", "read", "access", "download"))
    is_iam_change        = "iam" in service_lower or "setiampolicy" in method_lower
    is_denied            = authz_granted is False
    is_error             = not is_success

    # Presence flags
    has_principal     = principal is not None
    has_method        = method is not None
    has_service       = service is not None
    has_resource_name = resource_name is not None
    has_caller_ip     = caller_ip is not None
    has_user_agent    = user_agent is not None
    has_project       = project_id is not None
    has_permission    = permission is not None
    has_authz_info    = len(authz_info) > 0 if isinstance(authz_info, list) else bool(authz_info)
    has_timestamp     = timestamp is not None
    has_resource_type = resource_type is not None

    # ── T — Telemetry ────────────────────────────────────────────────────────
    core   = [has_principal, has_method, has_service, has_project, has_timestamp]
    resource_ctx = [has_resource_name, has_resource_type, has_permission]
    network_ctx  = [has_caller_ip, has_user_agent]
    auth_ctx     = [has_authz_info, _truthy(authz_granted)]

    t = (
        sum(1.0 for x in core if x) / max(len(core), 1) * 0.40 +
        sum(1.0 for x in resource_ctx if x) / max(len(resource_ctx), 1) * 0.25 +
        sum(1.0 for x in network_ctx if x) / max(len(network_ctx), 1) * 0.20 +
        sum(1.0 for x in auth_ctx if x) / max(len(auth_ctx), 1) * 0.15
    )

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    s = 0.30
    if is_high_risk_method:   s += 0.30
    if is_sensitive_service:  s += 0.15
    if is_iam_change:         s += 0.15
    if is_write_operation:    s += 0.05
    if is_delegated:          s += 0.10
    if is_denied:             s += 0.10
    if is_error:              s -= 0.05
    s = max(0.0, min(1.0, float(s)))

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    b = 0.35
    if has_principal:         b += 0.15
    if has_caller_ip:         b += 0.10
    if has_resource_name:     b += 0.10
    if has_authz_info:        b += 0.08
    if has_permission:        b += 0.07
    if has_user_agent:        b += 0.05
    if is_delegated:          b -= 0.05  # delegation = less direct accountability
    if is_denied:             b -= 0.05  # denied = incomplete action
    b = max(0.0, min(1.0, float(b)))

    flags = {
        "has_user":             has_principal,
        "has_host":             has_project,
        "has_command_line":     has_method,
        "has_process_path":     has_service,
        "has_parent_process":   has_resource_name,
        "has_principal":        has_principal,
        "has_method":           has_method,
        "has_service":          has_service,
        "has_resource_name":    has_resource_name,
        "has_caller_ip":        has_caller_ip,
        "has_user_agent":       has_user_agent,
        "has_project":          has_project,
        "has_permission":       has_permission,
        "has_authz_info":       has_authz_info,
        "is_high_risk_method":  is_high_risk_method,
        "is_sensitive_service": is_sensitive_service,
        "is_service_account":   is_service_account,
        "is_human_user":        is_human_user,
        "is_write_operation":   is_write_operation,
        "is_read_operation":    is_read_operation,
        "is_iam_change":        is_iam_change,
        "is_delegated":         is_delegated,
        "is_denied":            is_denied,
        "is_error":             is_error,
        "is_success":           is_success,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


def gcp_audit_to_inputs_and_flags(event):
    return extract(event)
