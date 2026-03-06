# dfs_core/features/azure_ad_signin.py
"""
Azure AD Sign-in Log → DFS Inputs

Azure AD Philosophy:
  Sign-in logs are the backbone of identity threat detection in Microsoft environments.
  Every Conditional Access policy failure, MFA challenge, risky sign-in, and impossible
  travel event flows through here.

  DFS's job: measure how trustworthy this sign-in event is for automated response.

  A sign-in with:
    - Full device context (compliant, hybrid-joined, device ID)
    - Strong auth (MFA satisfied, passwordless)
    - Known location + named network
    - Low risk level from Identity Protection
    - Consistent user agent
  ...is HIGH TRUST → automate block/allow decisions.

  A sign-in with:
    - Missing device context
    - Legacy auth protocol (SMTP, IMAP, ActiveSync)
    - Anonymous/Tor IP
    - High Identity Protection risk
    - Unfamiliar location
  ...is FRAGILE → human review required.

DFS Mapping:
  S (Signal Clarity):   Risk level + auth method + legacy protocol + IP risk signals
  T (Telemetry):        Completeness of identity + device + network + location context
  B (Behavioral):       Coherence of the sign-in narrative (MFA + device + CA policy)

Key fields (Microsoft Graph / Azure Monitor schema):
  userPrincipalName, userId, appId, appDisplayName
  ipAddress, location, deviceDetail
  authenticationRequirement, authenticationMethodsUsed
  conditionalAccessStatus, appliedConditionalAccessPolicies
  riskLevelAggregated, riskLevelDuringSignIn, riskState
  clientAppUsed, userAgent, correlationId
  status (errorCode, failureReason)
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
    if isinstance(v, str) and v.strip().lower() in ("", "-", "null", "none", "unknown", "n/a", "not applicable"):
        return False
    return True


def _clean(v: Any) -> Optional[str]:
    return str(v) if _truthy(v) else None


# ---------------------------------------------------------------------------
# Risk classification tables
# ---------------------------------------------------------------------------

# Identity Protection risk levels
_RISK_LEVEL_SCORE: Dict[str, float] = {
    "none":    0.05,
    "low":     0.35,
    "medium":  0.65,
    "high":    0.90,
    "hidden":  0.50,  # risk present but not disclosed
    "unknownFutureValue": 0.40,
}

# Legacy auth protocols — high risk, no MFA support
_LEGACY_AUTH_PROTOCOLS = {
    "exchange activesync",
    "smtp",
    "imap",
    "pop3",
    "mapi over http",
    "rpc over http",
    "other clients",
    "authenticated smtp",
    "autoDiscover",
}

# Auth methods that satisfy MFA
_MFA_METHODS = {
    "microsoft authenticator app",
    "fido2 security key",
    "windows hello for business",
    "hardware oath token",
    "software oath token",
    "sms",
    "voice",
    "phone app notification",
    "phone app otp",
    "passwordless",
}

# Conditional Access result risk
_CA_RESULT_RISK: Dict[str, float] = {
    "success":         0.00,   # CA passed
    "failure":         0.80,   # CA blocked
    "notApplied":      0.20,   # no policy matched
    "notEnabled":      0.30,   # CA disabled
    "unknownFutureValue": 0.20,
}


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract(
    event: Dict[str, Any],
    policy: Optional[Dict[str, Any]] = None,
) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Maps Azure AD Sign-in log entry → (DFSInputs, flags).

    Accepts Microsoft Graph signIn resource or Azure Monitor Log Analytics row.
    """

    # ── Core identity ────────────────────────────────────────────────────────
    upn              = _clean(event.get("userPrincipalName") or event.get("UserPrincipalName"))
    user_id          = _clean(event.get("userId") or event.get("UserId"))
    user_display     = _clean(event.get("userDisplayName") or event.get("UserDisplayName"))
    tenant_id        = _clean(event.get("tenantId") or event.get("TenantId") or event.get("ResourceTenantId"))
    correlation_id   = _clean(event.get("correlationId") or event.get("CorrelationId"))

    # ── Application ──────────────────────────────────────────────────────────
    app_id           = _clean(event.get("appId") or event.get("AppId"))
    app_name         = _clean(event.get("appDisplayName") or event.get("AppDisplayName"))
    resource_id      = _clean(event.get("resourceId") or event.get("ResourceId"))
    resource_name    = _clean(event.get("resourceDisplayName") or event.get("ResourceDisplayName"))

    # ── Network ──────────────────────────────────────────────────────────────
    ip_address       = _clean(event.get("ipAddress") or event.get("IpAddress"))
    location         = event.get("location") or event.get("Location") or {}
    city             = _clean(location.get("city") or location.get("City"))
    country          = _clean(location.get("countryOrRegion") or location.get("CountryOrRegion"))
    state            = _clean(location.get("state") or location.get("State"))
    lat              = _get(location, "geoCoordinates.latitude") or _get(location, "GeoCoordinates.Latitude")
    lon              = _get(location, "geoCoordinates.longitude") or _get(location, "GeoCoordinates.Longitude")
    named_location   = _clean(event.get("networkLocationDetails") or event.get("NetworkLocationDetails"))

    # ── Device ───────────────────────────────────────────────────────────────
    device           = event.get("deviceDetail") or event.get("DeviceDetail") or {}
    device_id        = _clean(device.get("deviceId") or device.get("DeviceId"))
    device_name      = _clean(device.get("displayName") or device.get("DisplayName"))
    device_os        = _clean(device.get("operatingSystem") or device.get("OperatingSystem"))
    device_browser   = _clean(device.get("browser") or device.get("Browser"))
    is_compliant     = device.get("isCompliant") or device.get("IsCompliant") or False
    is_managed       = device.get("isManaged") or device.get("IsManaged") or False
    trust_type       = _clean(device.get("trustType") or device.get("TrustType"))  # AzureAD, Hybrid, Workplace
    user_agent       = _clean(event.get("userAgent") or event.get("UserAgent") or device_browser)

    # ── Authentication ───────────────────────────────────────────────────────
    auth_requirement = _clean(event.get("authenticationRequirement") or event.get("AuthenticationRequirement"))
    auth_methods_raw = event.get("authenticationMethodsUsed") or event.get("AuthenticationMethodsUsed") or []
    auth_details     = event.get("authenticationDetails") or event.get("AuthenticationDetails") or []
    client_app       = _clean(event.get("clientAppUsed") or event.get("ClientAppUsed"))
    token_issuer     = _clean(event.get("tokenIssuerType") or event.get("TokenIssuerType"))

    # ── Conditional Access ───────────────────────────────────────────────────
    ca_status        = _clean(event.get("conditionalAccessStatus") or event.get("ConditionalAccessStatus"))
    ca_policies      = event.get("appliedConditionalAccessPolicies") or event.get("AppliedConditionalAccessPolicies") or []

    # ── Risk (Identity Protection) ───────────────────────────────────────────
    risk_aggregated  = _clean(event.get("riskLevelAggregated") or event.get("RiskLevelAggregated"))
    risk_during      = _clean(event.get("riskLevelDuringSignIn") or event.get("RiskLevelDuringSignIn"))
    risk_state       = _clean(event.get("riskState") or event.get("RiskState"))
    risk_detail      = _clean(event.get("riskDetail") or event.get("RiskDetail"))
    risk_event_types = event.get("riskEventTypes") or event.get("RiskEventTypes") or []
    risk_event_types_v2 = event.get("riskEventTypes_v2") or event.get("RiskEventTypes_v2") or []

    # ── Status ───────────────────────────────────────────────────────────────
    status           = event.get("status") or event.get("Status") or {}
    error_code       = status.get("errorCode") or status.get("ErrorCode") or 0
    failure_reason   = _clean(status.get("failureReason") or status.get("FailureReason"))
    is_successful    = int(error_code) == 0

    # ── Derived signals ──────────────────────────────────────────────────────
    client_app_lower = (client_app or "").lower()
    is_legacy_auth   = any(proto in client_app_lower for proto in _LEGACY_AUTH_PROTOCOLS)
    is_browser       = "browser" in client_app_lower
    is_modern_client = not is_legacy_auth and _truthy(client_app)

    auth_methods_lower = [str(m).lower() for m in auth_methods_raw]
    mfa_satisfied    = (
        any(m in _MFA_METHODS for m in auth_methods_lower)
        or auth_requirement == "multiFactorAuthentication"
        or any(
            d.get("authenticationStepResultDetail", "").lower() in ("mfa completed", "mfa requirement satisfied")
            for d in auth_details
        )
    )
    passwordless     = any("passwordless" in m for m in auth_methods_lower) or \
                       any("fido" in m for m in auth_methods_lower) or \
                       any("hello" in m for m in auth_methods_lower)

    risk_score       = _RISK_LEVEL_SCORE.get((risk_aggregated or risk_during or "none").lower(), 0.10)
    is_risky         = risk_score >= 0.65
    is_high_risk     = risk_score >= 0.85
    has_risk_events  = len(risk_event_types) > 0 or len(risk_event_types_v2) > 0

    ca_risk          = _CA_RESULT_RISK.get((ca_status or "notApplied").lower(), 0.20)
    ca_blocked       = ca_status == "failure"
    ca_passed        = ca_status == "success"

    is_hybrid_joined = (trust_type or "").lower() == "serveradjoin"
    is_azure_joined  = (trust_type or "").lower() == "azureadjoin"
    is_device_known  = device_id is not None
    has_geo          = lat is not None and lon is not None
    is_guest         = (token_issuer or "").lower() in ("aadguestuser", "microsoftaccountguest")

    # Impossible travel / anonymous proxy heuristics from risk events
    has_impossible_travel = any(
        "impossibleTravel" in str(e) or "impossible_travel" in str(e)
        for e in risk_event_types_v2
    )
    has_anonymous_ip = any(
        "anonymizedIpAddress" in str(e) or "anonymous" in str(e)
        for e in risk_event_types_v2
    )
    has_malware_ip   = any("maliciousIpAddress" in str(e) for e in risk_event_types_v2)
    has_leaked_creds = any("leakedCredentials" in str(e) for e in risk_event_types_v2)

    # ── Presence flags ───────────────────────────────────────────────────────
    has_upn           = upn is not None
    has_user_id       = user_id is not None
    has_tenant        = tenant_id is not None
    has_app           = app_id is not None
    has_resource      = resource_id is not None
    has_ip            = ip_address is not None
    has_location      = country is not None
    has_device_id     = device_id is not None
    has_device_os     = device_os is not None
    has_auth_method   = len(auth_methods_raw) > 0
    has_ca_status     = ca_status is not None
    has_risk_level    = _truthy(risk_aggregated) or _truthy(risk_during)
    has_correlation   = correlation_id is not None
    has_user_agent    = user_agent is not None

    # ── T — Telemetry Completeness ───────────────────────────────────────────
    core_fields    = [has_upn, has_user_id, has_tenant, has_app, has_ip, has_correlation]
    device_fields  = [has_device_id, has_device_os, is_device_known]
    auth_fields    = [has_auth_method, has_ca_status, _truthy(auth_requirement)]
    context_fields = [has_location, has_resource, has_risk_level, has_user_agent]

    core_t    = sum(1.0 for x in core_fields if x) / max(len(core_fields), 1)
    device_t  = sum(1.0 for x in device_fields if x) / max(len(device_fields), 1)
    auth_t    = sum(1.0 for x in auth_fields if x) / max(len(auth_fields), 1)
    context_t = sum(1.0 for x in context_fields if x) / max(len(context_fields), 1)

    t = (core_t * 0.40) + (device_t * 0.25) + (auth_t * 0.20) + (context_t * 0.15)

    # ── S — Signal Clarity ───────────────────────────────────────────────────
    s = risk_score * 0.50 + ca_risk * 0.20 + 0.30  # base

    if is_legacy_auth:          s = min(1.0, s + 0.20)  # legacy = no MFA possible
    if has_anonymous_ip:        s = min(1.0, s + 0.15)
    if has_malware_ip:          s = min(1.0, s + 0.18)
    if has_leaked_creds:        s = min(1.0, s + 0.20)
    if has_impossible_travel:   s = min(1.0, s + 0.15)
    if ca_blocked:              s = min(1.0, s + 0.10)  # CA blocked = confirmed policy violation
    if is_guest:                s = min(1.0, s + 0.08)

    # Good signals reduce concern
    if mfa_satisfied and not is_risky:     s = max(0.05, s - 0.10)
    if passwordless and not is_risky:      s = max(0.05, s - 0.08)
    if is_compliant and not is_risky:      s = max(0.05, s - 0.05)

    if not is_successful:       s = max(0.0, s - 0.10)  # failed logon = less actionable

    s = max(0.0, min(1.0, float(s)))

    # ── B — Behavioral Coherence ─────────────────────────────────────────────
    b = 0.35

    if has_upn:                 b += 0.10
    if has_device_id:           b += 0.10
    if is_compliant:            b += 0.08
    if is_managed:              b += 0.05
    if is_hybrid_joined or is_azure_joined: b += 0.07
    if mfa_satisfied:           b += 0.08
    if has_ca_status:           b += 0.05
    if has_location:            b += 0.05
    if has_auth_method:         b += 0.05
    if has_risk_level:          b += 0.02  # risk signal present = richer narrative

    # Incoherence penalties
    if is_legacy_auth:          b = max(0.0, b - 0.15)  # legacy breaks MFA narrative
    if ca_blocked:              b = max(0.0, b - 0.10)  # blocked = incomplete session
    if has_impossible_travel:   b = max(0.0, b - 0.08)

    b = max(0.0, min(1.0, float(b)))

    # ── Flags ────────────────────────────────────────────────────────────────
    flags = {
        # Standard DFS
        "has_user":             has_upn,
        "has_host":             has_device_id,
        "has_command_line":     has_auth_method,
        "has_process_path":     has_app,
        "has_parent_process":   has_resource,
        # Azure AD specific
        "has_upn":              has_upn,
        "has_user_id":          has_user_id,
        "has_tenant":           has_tenant,
        "has_app":              has_app,
        "has_resource":         has_resource,
        "has_ip":               has_ip,
        "has_location":         has_location,
        "has_geo":              has_geo,
        "has_device_id":        has_device_id,
        "has_device_os":        has_device_os,
        "has_auth_method":      has_auth_method,
        "has_ca_status":        has_ca_status,
        "has_risk_level":       has_risk_level,
        "has_user_agent":       has_user_agent,
        # Risk signals
        "is_legacy_auth":       is_legacy_auth,
        "is_modern_client":     is_modern_client,
        "mfa_satisfied":        mfa_satisfied,
        "passwordless":         passwordless,
        "is_compliant_device":  bool(is_compliant),
        "is_managed_device":    bool(is_managed),
        "is_hybrid_joined":     is_hybrid_joined,
        "is_azure_joined":      is_azure_joined,
        "is_risky":             is_risky,
        "is_high_risk":         is_high_risk,
        "ca_blocked":           ca_blocked,
        "ca_passed":            ca_passed,
        "is_guest":             is_guest,
        "is_successful":        is_successful,
        "has_risk_events":      has_risk_events,
        "has_impossible_travel": has_impossible_travel,
        "has_anonymous_ip":     has_anonymous_ip,
        "has_malware_ip":       has_malware_ip,
        "has_leaked_creds":     has_leaked_creds,
    }

    return DFSInputs(float(s), float(t), float(b)), flags


def azuread_signin_to_inputs_and_flags(event: Dict[str, Any]) -> Tuple[DFSInputs, Dict[str, bool]]:
    """Alias for registry compatibility."""
    return extract(event)
