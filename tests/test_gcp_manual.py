"""
Manual test for GCP Audit Log + SCC extractors.
Run: python test_gcp_manual.py
"""
import sys
sys.path.insert(0, ".")
from dfs_core.features.gcp_audit_log import extract as audit_extract
from dfs_core.features.gcp_scc import extract as scc_extract

# ── GCP Audit Log cases ──────────────────────────────────────────────────────
AUDIT_CASES = {
    "IAM policy change (full context)": {
        "protoPayload": {
            "methodName": "SetIamPolicy",
            "serviceName": "iam.googleapis.com",
            "resourceName": "projects/my-project/serviceAccounts/svc@my-project.iam.gserviceaccount.com",
            "authenticationInfo": {"principalEmail": "admin@corp.com"},
            "authorizationInfo": [{"permission": "iam.serviceAccounts.setIamPolicy", "granted": True}],
            "requestMetadata": {"callerIp": "203.0.113.10", "callerSuppliedUserAgent": "google-cloud-sdk/450"},
            "status": {"code": 0},
        },
        "resource": {"type": "service_account", "labels": {"project_id": "my-project"}},
        "severity": "NOTICE",
        "receiveTimestamp": "2024-01-15T10:30:00Z",
    },

    "Secret Manager access (sensitive read)": {
        "protoPayload": {
            "methodName": "AccessSecretVersion",
            "serviceName": "secretmanager.googleapis.com",
            "resourceName": "projects/my-project/secrets/db-password/versions/1",
            "authenticationInfo": {"principalEmail": "svc-deploy@my-project.iam.gserviceaccount.com"},
            "authorizationInfo": [{"permission": "secretmanager.versions.access", "granted": True}],
            "requestMetadata": {"callerIp": "10.0.1.5", "callerSuppliedUserAgent": "python-requests/2.28"},
            "status": {"code": 0},
        },
        "resource": {"type": "audited_resource", "labels": {"project_id": "my-project"}},
        "receiveTimestamp": "2024-01-15T10:31:00Z",
    },

    "Org policy change (critical, delegated)": {
        "protoPayload": {
            "methodName": "organizations.setIamPolicy",
            "serviceName": "cloudresourcemanager.googleapis.com",
            "resourceName": "organizations/123456789",
            "authenticationInfo": {
                "principalEmail": "attacker@external.com",
                "serviceAccountDelegationInfo": [{"principalSubject": "serviceAccount:svc@proj.iam.gserviceaccount.com"}],
            },
            "authorizationInfo": [{"permission": "resourcemanager.organizations.setIamPolicy", "granted": True}],
            "requestMetadata": {"callerIp": "198.51.100.42", "callerSuppliedUserAgent": "curl/7.88"},
            "status": {"code": 0},
        },
        "resource": {"type": "organization", "labels": {"project_id": "org-project"}},
        "receiveTimestamp": "2024-01-15T10:32:00Z",
    },

    "GCS bucket list (low risk read)": {
        "protoPayload": {
            "methodName": "storage.buckets.list",
            "serviceName": "storage.googleapis.com",
            "resourceName": "projects/my-project",
            "authenticationInfo": {"principalEmail": "dev@corp.com"},
            "requestMetadata": {"callerIp": "10.0.0.5"},
            "status": {"code": 0},
        },
        "resource": {"type": "gcs_bucket", "labels": {"project_id": "my-project"}},
        "receiveTimestamp": "2024-01-15T10:33:00Z",
    },

    "Denied IAM escalation attempt": {
        "protoPayload": {
            "methodName": "SetIamPolicy",
            "serviceName": "iam.googleapis.com",
            "resourceName": "projects/prod-project",
            "authenticationInfo": {"principalEmail": "contractor@external.com"},
            "authorizationInfo": [{"permission": "iam.projects.setIamPolicy", "granted": False}],
            "requestMetadata": {"callerIp": "185.220.101.10", "callerSuppliedUserAgent": "python/3.11"},
            "status": {"code": 7, "message": "Permission denied"},
        },
        "resource": {"type": "project", "labels": {"project_id": "prod-project"}},
        "receiveTimestamp": "2024-01-15T10:34:00Z",
    },
}

# ── GCP SCC cases ────────────────────────────────────────────────────────────
SCC_CASES = {
    "Reverse shell in container (critical)": {
        "finding": {
            "category": "REVERSE_SHELL",
            "severity": "CRITICAL",
            "state": "ACTIVE",
            "findingClass": "THREAT",
            "resourceName": "//container.googleapis.com/projects/my-proj/clusters/prod-cluster",
            "parent": "organizations/123456789/sources/etd",
            "name": "organizations/123456789/sources/etd/findings/abc123",
            "eventTime": "2024-01-15T10:30:00Z",
            "createTime": "2024-01-15T10:30:05Z",
            "mitreAttack": {
                "primaryTactic": "EXECUTION",
                "primaryTechniques": ["T1059.004"],
            },
            "indicator": {
                "ipAddresses": ["198.51.100.42", "185.220.101.10"],
                "domains": ["malicious.example.com"],
            },
            "connections": [{"destinationIp": "198.51.100.42", "destinationPort": 4444}],
            "processes": [{"binary": {"path": "/bin/bash"}, "args": ["-i"]}],
            "access": {
                "callerIp": "198.51.100.42",
                "principalEmail": "container-sa@my-proj.iam.gserviceaccount.com",
                "serviceName": "container.googleapis.com",
            },
            "sourceProperties": {"vm_instance_name": "gke-node-001", "container_name": "web-app"},
            "mute": "UNMUTED",
        }
    },

    "Anomalous IAM grant (high)": {
        "finding": {
            "category": "ANOMALOUS_IAM_GRANT",
            "severity": "HIGH",
            "state": "ACTIVE",
            "findingClass": "THREAT",
            "resourceName": "//cloudresourcemanager.googleapis.com/projects/my-proj",
            "parent": "organizations/123456789/sources/etd",
            "eventTime": "2024-01-15T10:35:00Z",
            "mitreAttack": {"primaryTactic": "PRIVILEGE_ESCALATION"},
            "access": {
                "callerIp": "203.0.113.99",
                "principalEmail": "attacker@external.com",
                "methodName": "SetIamPolicy",
            },
            "sourceProperties": {"externalMember": "user:backdoor@gmail.com"},
            "mute": "UNMUTED",
        }
    },

    "Public bucket misconfiguration (medium)": {
        "finding": {
            "category": "PUBLIC_BUCKET_ACL",
            "severity": "MEDIUM",
            "state": "ACTIVE",
            "findingClass": "MISCONFIGURATION",
            "resourceName": "//storage.googleapis.com/my-public-bucket",
            "parent": "organizations/123456789/sources/sha",
            "eventTime": "2024-01-15T10:40:00Z",
            "sourceProperties": {"bucket_policy_only": False},
            "mute": "UNMUTED",
        }
    },

    "Muted / already handled finding": {
        "finding": {
            "category": "CRYPTO_MINING",
            "severity": "HIGH",
            "state": "ACTIVE",
            "findingClass": "THREAT",
            "resourceName": "//compute.googleapis.com/projects/my-proj/instances/vm-001",
            "eventTime": "2024-01-14T08:00:00Z",
            "mute": "MUTED",
            "indicator": {"ipAddresses": ["pool.minergate.com"]},
        }
    },
}

def print_table(cases, extractor, title):
    print(f"\n{'='*76}")
    print(f"  {title}")
    print(f"{'='*76}")
    print(f"{'CASE':<46} {'S':>6} {'T':>6} {'B':>6} {'DFS':>7}")
    print(f"{'-'*76}")
    for name, event in cases.items():
        inputs, flags = extractor(event)
        dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)
        print(f"{name:<46} {inputs.signal:>6.3f} {inputs.trust:>6.3f} {inputs.overlap:>6.3f} {dfs:>7.4f}")
        risk = [k for k, v in flags.items() if v is True and (k.startswith("is_") or k.startswith("high_") or k.startswith("has_mitre") or k.startswith("has_indicators"))]
        if risk:
            print(f"  flags: {', '.join(risk[:6])}")
    print(f"{'='*76}")

print_table(AUDIT_CASES, audit_extract, "GCP AUDIT LOGS")
print_table(SCC_CASES, scc_extract, "GCP SECURITY COMMAND CENTER")
print()
