# dfs-core/tests/test_cloudtrail_iam.py
from dfs_core.pipeline import evaluate_event


def test_cloudtrail_iam_high_risk_scores_higher_than_degraded():
    high = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "sourceIPAddress": "198.51.100.10",
        "userAgent": "aws-cli/2.15",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/alice"},
        "additionalEventData": {"MFAUsed": "No"},
        "requestParameters": {"userName": "alice"},
    }

    degraded = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser"},
        "requestParameters": None,
    }

    r1 = evaluate_event(high, kind="aws-cloudtrail-iam", policy_path="policies/cloudtrail_iam.policy.json")
    r2 = evaluate_event(degraded, kind="aws-cloudtrail-iam", policy_path="policies/cloudtrail_iam.policy.json")

    assert r1.card.score > r2.card.score
