# dfs_core/features/gcp_scc.py
"""
Google Cloud Security Command Center (SCC) Finding → DFS Inputs

SCC is GCP's native threat detection platform.
Findings come from built-in detectors:
  - Event Threat Detection (ETD): real-time threats from audit logs
  - Container Threat Detection (CTD): GKE runtime threats
  - Virtual Machine Threat Detection (VMTD): memory threats
  - Web Security Scanner: app vulnerabilities
  - Security Health Analytics (SHA): misconfigurations

DFS Mapping:
  S: Finding category severity + source + active/inactive state
  T: Resource + asset + evidence completeness
  B: Coherence of finding narrative (indicators + MITRE + resource chain)

Key fields (SCC Finding proto):
  category, severity, state, findingClass
  resourceName, parent, name
  sourceProperties (varies by detector)
  indicator (ipAddresses, domains, signatures)
  mitreAttack (tactics, techniques)
  externalSystems, connections
  eventTime, createTime
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
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


# SCC severity → normalized risk
_SEVERITY_SCORE = {
    "CRITICAL": 0.95,
    "HIGH":     0.78,
    "MEDIUM":   0.55,
    "LOW":      0.25,
    "INFO":     0.10,
}

# SCC finding category risk tiers (ETD + CTD + VMTD)
_CATEGORY_RISK = {
    # Critical ETD categories
    "BACKDOOR":                         0.95,
    "CRYPTO_MINING":                    0.90,
    "DATA_EXFILTRATION":                0.93,
    "MALWARE_BAD_DOMAIN":               0.88,
    "MALWARE_BAD_IP":                   0.88,
    "OUTGOING_DOS":                     0.85,
    "PRIVILEGE_ESCALATION":             0.85,
    "DEFENSE_EVASION":                  0.80,
    "INITIAL_ACCESS":                   0.78,
    "CREDENTIAL_ACCESS":                0.82,
    "PERSISTENCE":                      0.80,
    "LATERAL_MOVEMENT":                 0.80,
    "EXFILTRATION":                     0.90,
    "IMPACT":                           0.88,
    # IAM / policy
    "EXTERNAL_MEMBER_ADDED_TO_POLICY":  0.75,
    "ADMIN_SERVICE_ACCOUNT":            0.70,
    "SERVICE_ACCOUNT_KEY_CREATED":      0.65,
    "ANOMALOUS_IAM_GRANT":              0.72,
    # Container
    "ADDED_BINARY_EXECUTED":            0.85,
    "REVERSE_SHELL":                    0.95,
    "CONTAINER_BREAKOUT_DETECTED":      0.93,
    "EXECUTION_TOCTOU":                 0.80,
    # Misconfig (SHA)
    "PUBLIC_BUCKET_ACL":                0.40,
    "OPEN_FIREWALL":                    0.45,
    "MFA_NOT_ENFORCED":                 0.50,
    "PUBLIC_IP_ADDRESS":                0.30,
}


def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:

    # Support both raw SCC finding and Pub/Sub notification wrapper
    finding = event.get("finding") or event

    category        = _clean(finding.get("category") or finding.get("Category"))
    severity_raw    = _clean(finding.get("severity") or finding.get("Severity") or "")
    state           = _clean(finding.get("state") or finding.get("State") or "ACTIVE")
    finding_class   = _clean(finding.get("findingClass") or finding.get("FindingClass"))
    resource_name   = _clean(finding.get("resourceName") or finding.get("ResourceName"))
    parent          = _clean(finding.get("parent") or finding.get("Parent"))
    finding_name    = _clean(finding.get("name") or finding.get("Name"))
    event_time      = _clean(finding.get("eventTime") or finding.get("EventTime"))
    create_time     = _clean(finding.get("createTime") or finding.get("CreateTime"))
    description     = _clean(finding.get("description") or finding.get("Description"))
    mute            = _clean(finding.get("mute") or finding.get("Mute") or "UNMUTED")

    # Source properties (varies per detector)
    src_props       = finding.get("sourceProperties") or finding.get("SourceProperties") or {}

    # Indicators (IPs, domains, signatures)
    indicator       = finding.get("indicator") or finding.get("Indicator") or {}
    indicator_ips   = indicator.get("ipAddresses") or indicator.get("IpAddresses") or []
    indicator_domains = indicator.get("domains") or indicator.get("Domains") or []
    indicator_sigs  = indicator.get("signatures") or indicator.get("Signatures") or []
    has_indicators  = len(indicator_ips) > 0 or len(indicator_domains) > 0 or len(indicator_sigs) > 0

    # MITRE ATT&CK
    mitre           = finding.get("mitreAttack") or finding.get("MitreAttack") or {}
    mitre_tactics   = mitre.get("primaryTactic") or mitre.get("PrimaryTactic")
    mitre_techniques = mitre.get("primaryTechniques") or mitre.get("PrimaryTechniques") or []
    has_mitre       = _truthy(mitre_tactics) or len(mitre_techniques) > 0

    # Connections (network)
    connections     = finding.get("connections") or finding.get("Connections") or []
    has_connections = len(connections) > 0

    # External systems (SIEM/SOAR integrations)
    external        = finding.get("externalSystems") or finding.get("ExternalSystems") or {}

    # Processes (from ETD/CTD)
    processes       = finding.get("processes") or finding.get("Processes") or []
    has_processes   = len(processes) > 0

    # Access context
    access          = finding.get("access") or finding.get("Access") or {}
    caller_ip       = _clean(access.get("callerIp") or access.get("CallerIp"))
    principal_email = _clean(access.get("principalEmail") or access.get("PrincipalEmail"))
    user_agent      = _clean(access.get("userAgentFamily") or access.get("UserAgentFamily"))
    service_name    = _clean(access.get("serviceName") or access.get("ServiceName"))
    method_name     = _clean(access.get("methodName") or access.get("MethodName"))

    # Derived
    severity_score  = _SEVERITY_SCORE.get((severity_raw or "").upper(), 0.30)
    category_risk   = _CATEGORY_RISK.get((category or "").upper(), 0.35)
    is_active       = (state or "").upper() == "ACTIVE"
    is_muted        = (mute or "").upper() == "MUTED"
    is_critical     = severity_score >= 0.90
    is_high         = severity_score >= 0.75
    is_threat       = (finding_class or "").upper() in ("THREAT", "VULNERABILITY")
    is_misconfiguration = (finding_class or "").upper() == "MISCONFIGURATION"
    has_network_ioc = len(indicator_ips) > 0 or has_connections
    high_ioc_count  = (len(indicator_ips) + len(indicator_domains)) >= 3

    # Presence flags
    has_category      = category is not None
    has_severity      = _truthy(severity_raw)
    has_resource      = resource_name is not None
    has_parent        = parent is not None
    has_finding_name  = finding_name is not None
    has_event_time    = event_time is not None
    has_source_props  = len(src_props) > 0
    has_caller_ip     = caller_ip is not None
    has_principal     = principal_email is not None
    has_user_agent    = user_agent is not None
    has_service       = service_name is not None
    has_method        = method_name is not None

    # ── T — Telemetry ────────────────────────────────────────────────────────
    core   = [has_category, has_severity, has_resource, has_parent, has_event_time]
    ioc    = [has_indicators, has_mitre, has_connections, has_processes]
    access_ctx = [has_caller_ip, has_principal, has_service, has_method]
    meta   = [has_source_props, has_finding_name, has_user_agent]

    t = (
        sum(1.0 for x in core if x) / max(len(core), 1) * 0.40 +
        sum(1.0 for x in ioc if x) / max(len(ioc), 1) * 0.30 +
        sum(1.0 for x in access_ctx if x) / max(len(access_ctx), 1) * 0.20 +
        sum(1.0 for x in meta if x) / max(len(meta), 1) * 0.10
    )

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    s = (category_risk * 0.55) + (severity_score * 0.45)
    if has_indicators:      s = min(1.0, s + 0.05)
    if high_ioc_count:      s = min(1.0, s + 0.05)
    if has_mitre:           s = min(1.0, s + 0.03)
    if has_network_ioc:     s = min(1.0, s + 0.03)
    if is_muted:            s = max(0.0, s - 0.25)  # muted = acknowledged/suppressed
    if not is_active:       s = max(0.0, s - 0.15)  # inactive = resolved
    s = max(0.0, min(1.0, float(s)))

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    b = 0.35
    if has_resource:        b += 0.12
    if has_principal:       b += 0.10
    if has_caller_ip:       b += 0.08
    if has_mitre:           b += 0.10  # MITRE mapping = structured threat narrative
    if has_indicators:      b += 0.08
    if has_processes:       b += 0.07
    if has_connections:     b += 0.05
    if has_source_props:    b += 0.05
    if is_muted:            b = max(0.0, b - 0.10)
    b = max(0.0, min(1.0, float(b)))

    flags = {
        "has_user":             has_principal,
        "has_host":             has_resource,
        "has_command_line":     has_method,
        "has_process_path":     has_service,
        "has_parent_process":   has_parent,
        "has_category":         has_category,
        "has_severity":         has_severity,
        "has_resource":         has_resource,
        "has_source_props":     has_source_props,
        "has_indicators":       has_indicators,
        "has_mitre":            has_mitre,
        "has_connections":      has_connections,
        "has_processes":        has_processes,
        "has_caller_ip":        has_caller_ip,
        "has_principal":        has_principal,
        "is_active":            is_active,
        "is_muted":             is_muted,
        "is_critical":          is_critical,
        "is_high":              is_high,
        "is_threat":            is_threat,
        "is_misconfiguration":  is_misconfiguration,
        "has_network_ioc":      has_network_ioc,
        "high_ioc_count":       high_ioc_count,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


def gcp_scc_to_inputs_and_flags(event):
    return extract(event)
