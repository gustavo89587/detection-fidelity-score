# examples/run_cloudtrail_iam_demo.py
from dfs_core.pipeline import evaluate_event

HIGH_RISK = {
    "eventVersion": "1.08",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "awsRegion": "us-east-1",
    "recipientAccountId": "123456789012",
    "sourceIPAddress": "198.51.100.10",
    "userAgent": "aws-cli/2.15",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/alice",
        "principalId": "AIDAEXAMPLE"
    },
    "additionalEventData": {"MFAUsed": "No"},
    "requestParameters": {"userName": "alice"}
}

DEGRADED = {
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "awsRegion": "us-east-1",
    "recipientAccountId": "123456789012",
    "userIdentity": {"type": "IAMUser"},
    "requestParameters": None
}

def main() -> None:
    for label, evt in [("HIGH_RISK", HIGH_RISK), ("DEGRADED", DEGRADED)]:
        res = evaluate_event(
            evt,
            kind="aws-cloudtrail-iam",
            policy_path="policies/cloudtrail_iam.policy.json"
        )
        print(f"\n=== {label} ===")
        print(res.card.to_dict())

if __name__ == "__main__":
    main()
