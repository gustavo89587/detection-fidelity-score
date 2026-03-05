# dfs_core/features/aws_cloudtrail_iam.py
from __future__ import annotations
from typing import Any, Dict, Tuple
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
    if isinstance(v, str) and v.strip() == "":
        return False
    return True


HIGH_RISK_IAM_EVENTS = {
    "CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey",
    "PutUserPolicy", "PutRolePolicy", "AttachUserPolicy", "AttachRolePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion", "CreateLoginProfile",
    "UpdateLoginProfile", "AddUserToGroup", "CreateUser", "CreateRole",
    "UpdateAssumeRolePolicy", "PassRole", "PutBucketPolicy",
}


def aws_cloudtrail_iam_to_inputs_and_flags(event: Dict[str, Any]) -> Tuple[DFSInputs, Dict[str, bool]]:
    event_name  = event.get("eventName")
    event_source = event.get("eventSource")
    region      = event.get("awsRegion")
    account     = event.get("recipientAccountId")
    src_ip      = event.get("sourceIPAddress")
    user_agent  = event.get("userAgent")
    id_type     = _get(event, "userIdentity.type")
    arn         = _get(event, "userIdentity.arn")
    principal   = _get(event, "userIdentity.principalId")
    mfa         = _get(event, "additionalEventData.MFAUsed")
    invoked_by  = _get(event, "userIdentity.invokedBy")
    req_params  = event.get("requestParameters")
    error_code  = event.get("errorCode")
    success     = not _truthy(error_code)
    is_high_risk = _truthy(event_name) and str(event_name) in HIGH_RISK_IAM_EVENTS

    flags = {
        "has_event_name":          _truthy(event_name),
        "has_event_source":        _truthy(event_source),
        "has_region":              _truthy(region),
        "has_account":             _truthy(account),
        "has_source_ip":           _truthy(src_ip),
        "has_user_agent":          _truthy(user_agent),
        "has_identity":            _truthy(arn) or _truthy(principal),
        "has_identity_type":       _truthy(id_type),
        "has_request_parameters":  req_params is not None,
        "has_success_outcome":     success,
        "has_mfa_signal":          _truthy(mfa),
        "is_high_risk_iam":        bool(is_high_risk),
        "is_service_invoked":      _truthy(invoked_by),
        "has_command_line":        True,
        "has_parent_process":      True,
        "has_user":                _truthy(arn) or _truthy(principal),
        "has_host":                _truthy(account),
        "has_process_path":        True,
    }

    telemetry_fields = [
        flags["has_event_name"], flags["has_event_source"], flags["has_region"],
        flags["has_account"], flags["has_source_ip"], flags["has_identity"],
        flags["has_request_parameters"],
    ]
    t = sum(1.0 for x in telemetry_fields if x) / float(len(telemetry_fields))

    s = 0.55
    if flags["has_event_name"] and flags["has_request_parameters"]:
        s += 0.20
    if flags["is_high_risk_iam"]:
        s += 0.20
    if flags["has_success_outcome"]:
        s += 0.05
    s = max(0.0, min(1.0, float(s)))

    b = 0.40
    if flags["has_identity"]:
        b += 0.20
    if flags["has_identity_type"]:
        b += 0.10
    if flags["has_mfa_signal"]:
        b += 0.10
    if flags["has_user_agent"]:
        b += 0.05
    if flags["is_service_invoked"]:
        b -= 0.05
    b = max(0.0, min(1.0, float(b)))

    return DFSInputs(float(s), float(t), float(b)), flags


def extract(event, policy=None):
    return aws_cloudtrail_iam_to_inputs_and_flags(event)
