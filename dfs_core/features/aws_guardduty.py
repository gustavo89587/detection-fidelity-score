# dfs_core/features/aws_guardduty.py
"""
AWS GuardDuty Finding → DFS Inputs

GuardDuty Philosophy:
  GuardDuty already does threat detection — it gives you a severity and a finding type.
  DFS's job here is NOT to re-detect the threat.
  DFS's job is to measure: "How much should I trust this finding for automation?"

  A GuardDuty finding with:
    - Full resource context (account, region, resource ARN)
    - Rich identity context (IAM role, principal, MFA)
    - Network context (src IP, geolocation, port)
    - Corroborating signals (multiple action types, consistent timeline)
  ...is a HIGH TRUST finding → automate the response.

  A GuardDuty finding with:
    - Missing resource ARN
    - No identity type
    - No network context
    - Single weak signal
  ...is FRAGILE → human review required.

DFS Mapping:
  S (Signal Clarity):   GuardDuty severity + finding type risk tier + action confidence
  T (Telemetry):        Resource + identity + network context completeness
  B (Behavioral):       Consistency of the threat narrative across all finding fields

Finding type risk tiers (GuardDuty naming convention: ThreatPurpose:ResourceType/ThreatFamilyName):
  CRITICAL  (0.90+): Backdoor, CryptoCurrency, Trojan, UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
  HIGH      (0.75+): Recon, Discovery with exfil indicators, PrivilegeEscalation
  MEDIUM    (0.55+): Policy violations, unusual API calls, PenTest tools
  LOW       (0.30+): Informational, expected behavior with weak signal
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

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
    if isinstance(v, str) and v.strip() in ("", "-", "null", "none", "unknown", "n/a"):
        return False
    return True


def _clean(v: Any) -> Optional[str]:
    return str(v) if _truthy(v) else None


# ---------------------------------------------------------------------------
# Finding type risk classification
# ---------------------------------------------------------------------------

# Maps finding type PREFIX → risk score
# GuardDuty format: "ThreatPurpose:ResourceType/ThreatFamilyName.DetailType"
_FINDING_TYPE_RISK: Dict[str, float] = {
    # Critical — automated response candidates
    "Backdoor":                         0.95,
    "CryptoCurrency":                   0.90,
    "Trojan":                           0.92,
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration": 0.95,
    "UnauthorizedAccess:EC2/TorClient": 0.88,
    "UnauthorizedAccess:EC2/TorRelay":  0.85,
    "Exfiltration":                     0.93,
    "Impact":                           0.90,

    # High — strong analyst signal
    "PrivilegeEscalation":              0.82,
    "Persistence":                      0.80,
    "UnauthorizedAccess":               0.75,
    "InitialAccess":                    0.75,
    "Execution":                        0.78,

    # Medium — worth investigating
    "Recon":                            0.60,
    "Discovery":                        0.55,
    "DefenseEvasion":                   0.65,
    "CredentialAccess":                 0.70,
    "LateralMovement":                  0.72,
    "Collection":                       0.60,

    # Low — informational / policy
    "Policy":                           0.30,
    "PenTest":                          0.45,
    "Stealth":                          0.50,
}

# GuardDuty severity → normalized risk (GuardDuty uses 0.1–8.9)
def _normalize_severity(severity: Any) -> float:
    try:
        s = float(severity)
        # GuardDuty: 7.0–8.9 = High, 4.0–6.9 = Medium, 0.1–3.9 = Low
        return min(1.0, s / 9.0)
    except (TypeError, ValueError):
        return 0.30


def _finding_type_risk(finding_type: Optional[str]) -> float:
    if not finding_type:
        return 0.30
    # Try longest prefix match
    for prefix, risk in sorted(_FINDING_TYPE_RISK.items(), key=lambda x: len(x[0]), reverse=True):
        if finding_type.startswith(prefix):
            return risk
    return 0.35  # unknown type — treat as low-medium


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps AWS GuardDuty finding → (DFSInputs, flags).

    Accepts both:
    - Raw GuardDuty finding JSON (from EventBridge/S3)
    - CloudWatch Events wrapper (detail field)
    """
    # Support both raw finding and CloudWatch Events wrapper
    finding = event.get("detail", event)

    # Core finding metadata
    finding_type  = _clean(finding.get("type") or finding.get("Type"))
    severity_raw  = finding.get("severity") or finding.get("Severity")
    account_id    = _clean(finding.get("accountId") or finding.get("AccountId"))
    region        = _clean(finding.get("region") or finding.get("Region"))
    finding_id    = _clean(finding.get("id") or finding.get("Id"))
    title         = _clean(finding.get("title") or finding.get("Title"))
    description   = _clean(finding.get("description") or finding.get("Description"))
    updated_at    = _clean(finding.get("updatedAt") or finding.get("UpdatedAt"))

    # Service context
    service       = finding.get("service") or finding.get("Service") or {}
    action        = service.get("action") or service.get("Action") or {}
    action_type   = _clean(action.get("actionType") or action.get("ActionType"))
    event_count   = service.get("count") or service.get("Count") or 1
    detector_id   = _clean(service.get("detectorId") or service.get("DetectorId"))
    archived      = service.get("archived") or service.get("Archived") or False
    evidence      = service.get("evidence") or service.get("Evidence") or {}
    threat_intel  = evidence.get("threatIntelligenceDetails") or []

    # Resource context
    resource      = finding.get("resource") or finding.get("Resource") or {}
    resource_type = _clean(resource.get("resourceType") or resource.get("ResourceType"))
    instance_details = resource.get("instanceDetails") or resource.get("InstanceDetails") or {}
    access_key_details = resource.get("accessKeyDetails") or resource.get("AccessKeyDetails") or {}
    s3_details    = resource.get("s3BucketDetails") or resource.get("S3BucketDetails") or []
    eks_details   = resource.get("eksClusterDetails") or resource.get("EksClusterDetails") or {}
    lambda_details = resource.get("lambdaDetails") or resource.get("LambdaDetails") or {}

    instance_id   = _clean(instance_details.get("instanceId") or instance_details.get("InstanceId"))
    instance_arn  = _clean(instance_details.get("iamInstanceProfile", {}).get("arn"))

    # Identity context
    principal_id  = _clean(access_key_details.get("principalId") or access_key_details.get("PrincipalId"))
    user_name     = _clean(access_key_details.get("userName") or access_key_details.get("UserName"))
    user_type     = _clean(access_key_details.get("userType") or access_key_details.get("UserType"))
    access_key_id = _clean(access_key_details.get("accessKeyId") or access_key_details.get("AccessKeyId"))

    # Network context (varies by action type)
    network_action = action.get("networkConnectionAction") or action.get("NetworkConnectionAction") or {}
    aws_api_action = action.get("awsApiCallAction") or action.get("AwsApiCallAction") or {}
    dns_action     = action.get("dnsRequestAction") or action.get("DnsRequestAction") or {}
    port_probe     = action.get("portProbeAction") or action.get("PortProbeAction") or {}

    remote_ip_details = (
        network_action.get("remoteIpDetails") or
        network_action.get("RemoteIpDetails") or
        aws_api_action.get("remoteIpDetails") or
        aws_api_action.get("RemoteIpDetails") or {}
    )

    src_ip        = _clean(remote_ip_details.get("ipAddressV4") or remote_ip_details.get("IpAddressV4"))
    src_country   = _clean(_get(remote_ip_details, "country.countryName") or _get(remote_ip_details, "Country.CountryName"))
    src_org       = _clean(_get(remote_ip_details, "organization.org") or _get(remote_ip_details, "Organization.Org"))
    src_asn       = _clean(_get(remote_ip_details, "organization.asn") or _get(remote_ip_details, "Organization.Asn"))
    is_tor        = bool(remote_ip_details.get("ipAddressV4")) and (
        "tor" in (src_org or "").lower() or "tor" in (finding_type or "").lower()
    )

    api_called    = _clean(aws_api_action.get("api") or aws_api_action.get("Api"))
    api_service   = _clean(aws_api_action.get("serviceName") or aws_api_action.get("ServiceName"))
    caller_type   = _clean(aws_api_action.get("callerType") or aws_api_action.get("CallerType"))
    user_agent    = _clean(aws_api_action.get("userAgent") or aws_api_action.get("UserAgent"))
    error_code    = _clean(aws_api_action.get("errorCode") or aws_api_action.get("ErrorCode"))

    # Threat intel hits
    has_threat_intel = len(threat_intel) > 0

    # -----------------------------------------------------------------------
    # Derived risk signals
    # -----------------------------------------------------------------------
    severity_score   = _normalize_severity(severity_raw)
    type_risk        = _finding_type_risk(finding_type)
    is_high_severity = severity_score >= 0.78   # GuardDuty >= 7.0
    is_med_severity  = severity_score >= 0.44   # GuardDuty >= 4.0
    is_archived      = bool(archived)
    high_event_count = int(event_count) >= 10
    is_ec2_finding   = resource_type == "Instance" or instance_id is not None
    is_iam_finding   = resource_type in ("AccessKey", "User") or user_type is not None
    is_s3_finding    = bool(s3_details)
    is_eks_finding   = bool(eks_details)
    is_lambda_finding = bool(lambda_details)

    # -----------------------------------------------------------------------
    # Presence flags
    # -----------------------------------------------------------------------
    has_finding_type  = finding_type is not None
    has_severity      = _truthy(severity_raw)
    has_account       = account_id is not None
    has_region        = region is not None
    has_finding_id    = finding_id is not None
    has_resource_type = resource_type is not None
    has_resource_id   = instance_id is not None or principal_id is not None or bool(s3_details)
    has_identity      = principal_id is not None or user_name is not None
    has_identity_type = user_type is not None
    has_src_ip        = src_ip is not None
    has_geo           = src_country is not None
    has_asn           = src_asn is not None
    has_action_type   = action_type is not None
    has_api_call      = api_called is not None
    has_user_agent    = user_agent is not None
    has_detector      = detector_id is not None
    has_description   = description is not None
    has_updated_at    = updated_at is not None

    # -----------------------------------------------------------------------
    # T — Telemetry Completeness
    # -----------------------------------------------------------------------
    core_fields = [
        has_finding_type, has_severity, has_account,
        has_region, has_finding_id, has_resource_type,
    ]
    resource_fields = [has_resource_id, has_action_type]
    identity_fields = [has_identity, has_identity_type] if is_iam_finding else [has_identity]
    network_fields  = [has_src_ip] if action_type in ("NETWORK_CONNECTION", "AWS_API_CALL", "PORT_PROBE") else []
    enrichment      = [has_geo, has_asn, has_user_agent, has_threat_intel, has_detector]

    core_t      = sum(1.0 for x in core_fields if x) / max(len(core_fields), 1)
    resource_t  = sum(1.0 for x in resource_fields if x) / max(len(resource_fields), 1)
    identity_t  = sum(1.0 for x in identity_fields if x) / max(len(identity_fields), 1) if identity_fields else 1.0
    network_t   = sum(1.0 for x in network_fields if x) / max(len(network_fields), 1) if network_fields else 1.0
    enrich_t    = sum(1.0 for x in enrichment if x) / max(len(enrichment), 1)

    t = (core_t * 0.40) + (resource_t * 0.20) + (identity_t * 0.15) + (network_t * 0.15) + (enrich_t * 0.10)

    # -----------------------------------------------------------------------
    # S — Signal Clarity
    # -----------------------------------------------------------------------
    # Blend finding type risk and GuardDuty severity
    s = (type_risk * 0.60) + (severity_score * 0.40)

    # Boost for corroborating signals
    if has_threat_intel:        s = min(1.0, s + 0.05)
    if high_event_count:        s = min(1.0, s + 0.05)
    if is_tor:                  s = min(1.0, s + 0.08)
    if has_api_call:            s = min(1.0, s + 0.03)
    if error_code:              s = min(1.0, s - 0.05)  # failed API call = less confident

    # Archived finding = already reviewed, lower automation signal
    if is_archived:             s = max(0.0, s - 0.20)

    s = max(0.0, min(1.0, float(s)))

    # -----------------------------------------------------------------------
    # B — Behavioral Coherence
    # -----------------------------------------------------------------------
    b = 0.40

    if has_finding_type:        b += 0.10
    if has_resource_id:         b += 0.10
    if has_identity:            b += 0.10
    if has_src_ip:              b += 0.08
    if has_geo:                 b += 0.05
    if has_action_type:         b += 0.05
    if has_api_call:            b += 0.05
    if has_threat_intel:        b += 0.05
    if high_event_count:        b += 0.02  # repeated pattern = more coherent

    # IAM findings without identity = broken narrative
    if is_iam_finding and not has_identity:
        b = max(0.0, b - 0.15)

    b = max(0.0, min(1.0, float(b)))

    # -----------------------------------------------------------------------
    # Flags
    # -----------------------------------------------------------------------
    flags = {
        # Standard DFS flags
        "has_user":             has_identity,
        "has_host":             has_account,
        "has_command_line":     has_api_call,
        "has_process_path":     has_resource_type,
        "has_parent_process":   has_action_type,
        # GuardDuty-specific
        "has_finding_type":     has_finding_type,
        "has_severity":         has_severity,
        "has_account":          has_account,
        "has_region":           has_region,
        "has_resource_id":      has_resource_id,
        "has_identity":         has_identity,
        "has_identity_type":    has_identity_type,
        "has_src_ip":           has_src_ip,
        "has_geo":              has_geo,
        "has_asn":              has_asn,
        "has_action_type":      has_action_type,
        "has_api_call":         has_api_call,
        "has_user_agent":       has_user_agent,
        "has_threat_intel":     has_threat_intel,
        "has_detector":         has_detector,
        # Risk signals
        "is_high_severity":     is_high_severity,
        "is_med_severity":      is_med_severity,
        "is_archived":          is_archived,
        "is_tor":               is_tor,
        "is_ec2_finding":       is_ec2_finding,
        "is_iam_finding":       is_iam_finding,
        "is_s3_finding":        is_s3_finding,
        "is_eks_finding":       is_eks_finding,
        "is_lambda_finding":    is_lambda_finding,
        "high_event_count":     high_event_count,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


def guardduty_to_inputs_and_flags(event: Dict[str, Any]) -> Tuple[DFSInputs, Dict[str, bool]]:
    """Alias for registry compatibility."""
    return extract(event)
