# dfs_core/features/aws_cloudtrail_iam.py
from __future__ import annotations

from typing import Any, Dict, Tuple

from dfs_core.scoring import DFSInputs
from dfs_core.features.registry import register


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


# A very small, high-signal IAM surface (expand later)
HIGH_RISK_IAM_EVENTS = {
    "CreateAccessKey",
    "UpdateAccessKey",
    "DeleteAccessKey",
    "PutUserPolicy",
    "PutRolePolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "AddUserToGroup",
    "CreateUser",
    "CreateRole",
    "UpdateAssumeRolePolicy",
    "PassRole",
    "PutBucketPolicy",  # S3 policy changes are often blast-radius
}


def aws_cloudtrail_iam_to_inputs_and_flags(event: Dict[str, Any]) -> Tuple[DFSInputs, Dict[str, bool]]:
    """
    Expected (loosely) CloudTrail-like structure:
      eventName, eventSource, userIdentity, sourceIPAddress, userAgent,
      requestParameters, responseElements, recipientAccountId, awsRegion, errorCode, errorMessage

    DFS mapping idea:
      - S (signal clarity): is intent/action explicit? is it a high-risk IAM action? success vs error?
      - T (telemetry completeness): do we have principal + source ip + region + account + request params?
      - B (behavioral coherence): do we have identity type + MFA indicator + user agent + anomalies hints?
    """

    event_name = event.get("eventName")
    event_source = event.get("eventSource")
    region = event.get("awsRegion")
    account = event.get("recipientAccountId")
    src_ip = event.get("sourceIPAddress")
    user_agent = event.get("userAgent")

    # Identity fields
    id_type = _get(event, "userIdentity.type")
    arn = _get(event, "userIdentity.arn")
    principal = _get(event, "userIdentity.principalId")
    mfa = _get(event, "additionalEventData.MFAUsed")  # often "Yes"/"No"
    invoked_by = _get(event, "userIdentity.invokedBy")  # AWS service invoked-by

    req_params = event.get("requestParameters")
    resp = event.get("responseElements")

    error_code = event.get("errorCode")
    success = not _truthy(error_code)

    is_high_risk = _truthy(event_name) and str(event_name) in HIGH_RISK_IAM_EVENTS

    # Flags (context presence)
    flags = {
        "has_event_name": _truthy(event_name),
        "has_event_source": _truthy(event_source),
        "has_region": _truthy(region),
        "has_account": _truthy(account),
        "has_source_ip": _truthy(src_ip),
        "has_user_agent": _truthy(user_agent),
        "has_identity": _truthy(arn) or _truthy(principal),
        "has_identity_type": _truthy(id_type),
        "has_request_parameters": req_params is not None,
        "has_success_outcome": success,
        "has_mfa_signal": _truthy(mfa),
        "is_high_risk_iam": bool(is_high_risk),
        "is_service_invoked": _truthy(invoked_by),
    }

    # Telemetry completeness (T)
    telemetry_fields = [
        flags["has_event_name"],
        flags["has_event_source"],
        flags["has_region"],
        flags["has_account"],
        flags["has_source_ip"],
        flags["has_identity"],
        flags["has_request_parameters"],
    ]
    t = sum(1.0 for x in telemetry_fields if x) / float(len(telemetry_fields))

    # Signal clarity (S)
    # IAM changes are explicit actions: if high-risk + success + request params -> clarity high
    s = 0.55
    if flags["has_event_name"] and flags["has_request_parameters"]:
        s += 0.20
    if flags["is_high_risk_iam"]:
        s += 0.20
    if flags["has_success_outcome"]:
        s += 0.05
    s = max(0.0, min(1.0, float(s)))

    # Behavioral coherence (B)
    # Identity + type + MFA signal tends to be key for decision confidence in IAM events.
    b = 0.40
    if flags["has_identity"]:
        b += 0.20
    if flags["has_identity_type"]:
        b += 0.10
    if flags["has_mfa_signal"]:
        b += 0.10
    if flags["has_user_agent"]:
        b += 0.05
    # Service-invoked actions reduce human intent clarity (not always bad), keep conservative:
    if flags["is_service_invoked"]:
        b -= 0.05
    b = max(0.0, min(1.0, float(b)))

    return DFSInputs(float(s), float(t), float(b)), {
        # normalize for explain_score penalties keys
        "has_command_line": True,          # N/A in cloud; don't penalize with 4688 keys
        "has_parent_process": True,        # N/A in cloud
        "has_user": flags["has_identity"],
        "has_host": flags["has_account"],
        "has_process_path": True,          # N/A in cloud
        # Keep full flags too (optional consumers)
        **flags,
    }


# Register kinds
register("aws-cloudtrail-iam", aws_cloudtrail_iam_to_inputs_and_flags)
register("cloudtrail-iam", aws_cloudtrail_iam_to_inputs_and_flags)
