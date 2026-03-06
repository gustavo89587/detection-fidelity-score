"""
Manual test for windows_4624 extractor.
Run: python test_4624_manual.py
"""
import sys
sys.path.insert(0, ".")

from dfs_core.features.windows_4624 import extract

# ── Test cases ──────────────────────────────────────────────────────────────

CASES = {
    "RDP full context (gold)": {
        "event": {"code": 4624},
        "host": {"name": "DC-01"},
        "user": {"domain": "CORP", "name": "administrator"},
        "source": {"ip": "198.51.100.50", "port": "49812"},
        "process": {"executable": r"C:\Windows\System32\svchost.exe"},
        "winlog": {"event_data": {
            "LogonType": "10",
            "WorkstationName": "WS-091",
            "AuthenticationPackageName": "Negotiate",
            "TargetLogonId": "0x3e7",
            "SubjectUserName": "SYSTEM",
            "SubjectDomainName": "NT AUTHORITY",
            "ImpersonationLevel": "%%1833",
            "ElevatedToken": "%%1842",
        }},
    },

    "RDP missing source IP (degraded)": {
        "event": {"code": 4624},
        "host": {"name": "DC-01"},
        "user": {"domain": "CORP", "name": "administrator"},
        "winlog": {"event_data": {
            "LogonType": "10",
            "WorkstationName": "[MISSING]",
        }},
    },

    "NTLM network logon (lateral movement signal)": {
        "event": {"code": 4624},
        "host": {"name": "FILE-SRV-02"},
        "user": {"domain": "CORP", "name": "jdoe"},
        "source": {"ip": "10.0.1.55"},
        "winlog": {"event_data": {
            "LogonType": "3",
            "WorkstationName": "WS-099",
            "AuthenticationPackageName": "NTLM",
            "LmPackageName": "NTLM V2",
            "TargetLogonId": "0x1a2b3c",
            "SubjectUserName": "jdoe",
        }},
    },

    "Cleartext network logon (critical)": {
        "event": {"code": 4624},
        "host": {"name": "LEGACY-SRV"},
        "user": {"domain": "CORP", "name": "svc_backup"},
        "source": {"ip": "10.0.2.10"},
        "winlog": {"event_data": {
            "LogonType": "8",
            "AuthenticationPackageName": "MSV1_0",
            "WorkstationName": "WS-OLD",
        }},
    },

    "runas /netonly (lateral movement setup)": {
        "event": {"code": 4624},
        "host": {"name": "WS-DEV-01"},
        "user": {"domain": "CORP", "name": "jdoe"},
        "winlog": {"event_data": {
            "LogonType": "9",
            "AuthenticationPackageName": "Negotiate",
            "WorkstationName": "WS-DEV-01",
        }},
    },

    "Anonymous logon (attack indicator)": {
        "event": {"code": 4624},
        "host": {"name": "FILE-SRV-01"},
        "user": {"name": "Anonymous Logon", "domain": "NT AUTHORITY"},
        "source": {"ip": "192.168.1.200"},
        "winlog": {"event_data": {
            "LogonType": "3",
            "AuthenticationPackageName": "NTLM",
        }},
    },

    "Interactive console logon (low risk baseline)": {
        "event": {"code": 4624},
        "host": {"name": "WS-001"},
        "user": {"domain": "CORP", "name": "jdoe"},
        "winlog": {"event_data": {
            "LogonType": "2",
            "WorkstationName": "WS-001",
            "AuthenticationPackageName": "Kerberos",
            "TargetLogonId": "0x4f2a1",
            "SubjectUserName": "jdoe",
        }},
    },
}

# ── Run ──────────────────────────────────────────────────────────────────────

print(f"\n{'='*72}")
print(f"{'CASE':<42} {'S':>6} {'T':>6} {'B':>6} {'DFS':>7}")
print(f"{'='*72}")

for name, event in CASES.items():
    inputs, flags = extract(event)
    dfs = round(inputs.signal * inputs.trust * inputs.overlap, 4)
    print(f"{name:<42} {inputs.signal:>6.3f} {inputs.trust:>6.3f} {inputs.overlap:>6.3f} {dfs:>7.4f}")
    # show active risk flags
    risk_flags = [k for k, v in flags.items() if v is True and k.startswith("is_")]
    if risk_flags:
        print(f"  {'':42} risk: {', '.join(risk_flags)}")

print(f"{'='*72}\n")