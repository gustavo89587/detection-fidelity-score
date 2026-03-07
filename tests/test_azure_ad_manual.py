"""
Manual test for Azure AD Sign-in extractor.
Run: python test_azure_ad_manual.py
"""
import sys
sys.path.insert(0, ".")
from dfs_core.features.azure_ad_signin import extract

CASES = {
    "Compliant device + MFA + low risk (gold)": {
        "userPrincipalName": "alice@corp.com",
        "userId": "user-001",
        "tenantId": "tenant-001",
        "appId": "app-001",
        "appDisplayName": "Microsoft 365",
        "resourceId": "res-001",
        "ipAddress": "203.0.113.10",
        "correlationId": "corr-001",
        "location": {"city": "Seattle", "countryOrRegion": "US", "state": "WA",
                     "geoCoordinates": {"latitude": 47.6, "longitude": -122.3}},
        "deviceDetail": {
            "deviceId": "dev-001", "displayName": "ALICE-LAPTOP",
            "operatingSystem": "Windows 10", "browser": "Chrome",
            "isCompliant": True, "isManaged": True, "trustType": "AzureADJoined",
        },
        "authenticationRequirement": "multiFactorAuthentication",
        "authenticationMethodsUsed": ["Microsoft Authenticator App"],
        "clientAppUsed": "Browser",
        "conditionalAccessStatus": "success",
        "riskLevelAggregated": "none",
        "riskLevelDuringSignIn": "none",
        "riskState": "none",
        "riskEventTypes_v2": [],
        "status": {"errorCode": 0},
        "userAgent": "Mozilla/5.0 Chrome/120",
    },

    "Legacy auth SMTP (no MFA possible)": {
        "userPrincipalName": "bob@corp.com",
        "userId": "user-002",
        "tenantId": "tenant-001",
        "appId": "app-smtp",
        "appDisplayName": "SMTP Auth Client",
        "ipAddress": "198.51.100.55",
        "correlationId": "corr-002",
        "location": {"countryOrRegion": "US"},
        "clientAppUsed": "SMTP",
        "authenticationMethodsUsed": ["Password"],
        "conditionalAccessStatus": "notApplied",
        "riskLevelAggregated": "low",
        "riskEventTypes_v2": [],
        "status": {"errorCode": 0},
    },

    "High risk + impossible travel + leaked creds": {
        "userPrincipalName": "ceo@corp.com",
        "userId": "user-003",
        "tenantId": "tenant-001",
        "appId": "app-001",
        "ipAddress": "185.220.101.42",
        "correlationId": "corr-003",
        "location": {"countryOrRegion": "RU"},
        "deviceDetail": {"operatingSystem": "Unknown"},
        "clientAppUsed": "Browser",
        "authenticationMethodsUsed": ["Password"],
        "conditionalAccessStatus": "failure",
        "riskLevelAggregated": "high",
        "riskLevelDuringSignIn": "high",
        "riskState": "atRisk",
        "riskEventTypes_v2": [
            "impossibleTravel", "anonymizedIpAddress", "leakedCredentials"
        ],
        "status": {"errorCode": 0},
    },

    "CA blocked + anonymous IP": {
        "userPrincipalName": "dave@corp.com",
        "userId": "user-004",
        "tenantId": "tenant-001",
        "appId": "app-002",
        "ipAddress": "10.8.0.1",
        "correlationId": "corr-004",
        "location": {"countryOrRegion": "NL"},
        "clientAppUsed": "Browser",
        "authenticationMethodsUsed": [],
        "conditionalAccessStatus": "failure",
        "riskLevelAggregated": "medium",
        "riskEventTypes_v2": ["anonymizedIpAddress"],
        "status": {"errorCode": 53003, "failureReason": "Blocked by Conditional Access"},
    },

    "Guest user + no device context": {
        "userPrincipalName": "guest@partner.com",
        "userId": "user-005",
        "tenantId": "tenant-001",
        "appId": "app-teams",
        "ipAddress": "203.0.113.99",
        "correlationId": "corr-005",
        "tokenIssuerType": "AadGuestUser",
        "clientAppUsed": "Browser",
        "authenticationMethodsUsed": ["Password"],
        "conditionalAccessStatus": "notApplied",
        "riskLevelAggregated": "none",
        "riskEventTypes_v2": [],
        "status": {"errorCode": 0},
    },

    "Passwordless + compliant + low risk (ideal)": {
        "userPrincipalName": "eve@corp.com",
        "userId": "user-006",
        "tenantId": "tenant-001",
        "appId": "app-001",
        "resourceId": "res-001",
        "ipAddress": "203.0.113.20",
        "correlationId": "corr-006",
        "location": {"city": "NYC", "countryOrRegion": "US",
                     "geoCoordinates": {"latitude": 40.7, "longitude": -74.0}},
        "deviceDetail": {
            "deviceId": "dev-006", "displayName": "EVE-SURFACE",
            "operatingSystem": "Windows 11", "browser": "Edge",
            "isCompliant": True, "isManaged": True, "trustType": "AzureADJoined",
        },
        "authenticationRequirement": "multiFactorAuthentication",
        "authenticationMethodsUsed": ["FIDO2 Security Key"],
        "clientAppUsed": "Browser",
        "conditionalAccessStatus": "success",
        "riskLevelAggregated": "none",
        "riskEventTypes_v2": [],
        "status": {"errorCode": 0},
    },
}

print(f"\n{'='*78}")
print(f"{'CASE':<44} {'S':>6} {'T':>6} {'B':>6} {'DFS':>7}")
print(f"{'='*78}")

for name, event in CASES.items():
    inputs, flags = extract(event)
    dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)
    print(f"{name:<44} {inputs.signal:>6.3f} {inputs.trust:>6.3f} {inputs.overlap:>6.3f} {dfs:>7.4f}")
    risk_flags = [k for k, v in flags.items() if v is True and (
        k.startswith("is_") or k.startswith("has_impossible") or
        k.startswith("has_anonymous") or k.startswith("has_malware") or
        k.startswith("has_leaked") or k in ("ca_blocked", "mfa_satisfied", "passwordless")
    )]
    if risk_flags:
        print(f"  flags: {', '.join(risk_flags)}")

print(f"{'='*78}\n")
