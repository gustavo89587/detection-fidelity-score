"""
Manual test for AWS GuardDuty extractor.
Run: python test_guardduty_manual.py
"""
import sys
sys.path.insert(0, ".")

from dfs_core.features.aws_guardduty import extract

CASES = {
    "InstanceCredentialExfiltration (critical, full context)": {
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "severity": 8.5,
        "accountId": "123456789012",
        "region": "us-east-1",
        "id": "abc123",
        "title": "EC2 instance credentials used from external IP",
        "description": "EC2 instance role credentials used from IP outside AWS.",
        "updatedAt": "2024-01-15T10:30:00Z",
        "service": {
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {
                    "api": "GetCallerIdentity",
                    "serviceName": "sts.amazonaws.com",
                    "callerType": "Remote IP",
                    "userAgent": "aws-cli/2.15.0",
                    "remoteIpDetails": {
                        "ipAddressV4": "203.0.113.42",
                        "country": {"countryName": "Russia"},
                        "organization": {"org": "VPN Provider", "asn": "AS12345"},
                    },
                },
            },
            "detectorId": "abc123detector",
            "count": 47,
            "evidence": {
                "threatIntelligenceDetails": [{"threatListName": "ProofPoint", "threatNames": ["Scanner"]}]
            },
        },
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-0abc123def456"},
            "accessKeyDetails": {
                "principalId": "AROAEXAMPLE:i-0abc123def456",
                "userType": "AssumedRole",
                "userName": "EC2InstanceRole",
                "accessKeyId": "ASIAEXAMPLE",
            },
        },
    },

    "Recon:IAMUser/MaliciousIPCaller (medium)": {
        "type": "Recon:IAMUser/MaliciousIPCaller",
        "severity": 5.0,
        "accountId": "123456789012",
        "region": "eu-west-1",
        "id": "def456",
        "service": {
            "action": {
                "actionType": "AWS_API_CALL",
                "awsApiCallAction": {
                    "api": "ListUsers",
                    "serviceName": "iam.amazonaws.com",
                    "remoteIpDetails": {
                        "ipAddressV4": "198.51.100.10",
                        "country": {"countryName": "China"},
                        "organization": {"org": "Cloud Host", "asn": "AS9876"},
                    },
                },
            },
            "detectorId": "detector456",
            "count": 3,
        },
        "resource": {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "principalId": "AIDAEXAMPLE",
                "userType": "IAMUser",
                "userName": "ci-deploy",
                "accessKeyId": "AKIAEXAMPLE",
            },
        },
    },

    "CryptoCurrency:EC2/BitcoinTool (high, no identity)": {
        "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "severity": 7.5,
        "accountId": "123456789012",
        "region": "us-west-2",
        "id": "ghi789",
        "service": {
            "action": {
                "actionType": "DNS_REQUEST",
                "dnsRequestAction": {"domain": "pool.minergate.com", "blocked": False},
            },
            "detectorId": "detector789",
            "count": 120,
        },
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": "i-0xyz987"},
        },
    },

    "Policy:S3/BucketPublicAccessGranted (low risk)": {
        "type": "Policy:S3/BucketPublicAccessGranted",
        "severity": 2.0,
        "accountId": "123456789012",
        "region": "us-east-1",
        "id": "jkl000",
        "service": {
            "action": {"actionType": "AWS_API_CALL"},
            "detectorId": "detectorABC",
            "count": 1,
        },
        "resource": {
            "resourceType": "S3Bucket",
            "s3BucketDetails": [{"name": "my-public-bucket", "type": "Destination"}],
        },
    },

    "High severity, missing context (degraded)": {
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "severity": 8.0,
        "accountId": "123456789012",
        "service": {
            "action": {"actionType": "AWS_API_CALL"},
            "count": 1,
        },
        "resource": {"resourceType": "AccessKey"},
    },

    "Archived finding (already handled)": {
        "type": "Backdoor:EC2/C&CActivity.B",
        "severity": 8.0,
        "accountId": "123456789012",
        "region": "us-east-1",
        "id": "archived123",
        "service": {
            "archived": True,
            "action": {"actionType": "NETWORK_CONNECTION"},
            "detectorId": "detectorXYZ",
            "count": 5,
        },
        "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": "i-old"}},
    },
}

print(f"\n{'='*76}")
print(f"{'CASE':<46} {'S':>6} {'T':>6} {'B':>6} {'DFS':>7}")
print(f"{'='*76}")

for name, event in CASES.items():
    inputs, flags = extract(event)
    dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)
    print(f"{name:<46} {inputs.signal:>6.3f} {inputs.trust:>6.3f} {inputs.overlap:>6.3f} {dfs:>7.4f}")
    risk_flags = [k for k, v in flags.items() if v is True and (k.startswith("is_") or k.startswith("high_"))]
    if risk_flags:
        print(f"  risk: {', '.join(risk_flags)}")

print(f"{'='*76}\n")
