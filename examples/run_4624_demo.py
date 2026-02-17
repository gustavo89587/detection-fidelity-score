# examples/run_4624_demo.py
from dfs_core.pipeline import evaluate_event

PRIV_RDP = {
    "event": {"code": 4624},
    "host": {"name": "DC-01"},
    "user": {"domain": "CORP", "name": "administrator"},
    "source": {"ip": "198.51.100.50"},
    "winlog": {"event_data": {"LogonType": "10", "WorkstationName": "WS-091", "AuthenticationPackageName": "Negotiate"}},
    "process": {"executable": r"C:\Windows\System32\svchost.exe"}
}

SOC_NETWORK = {
    "event": {"code": 4624},
    "host": {"name": "FILE-01"},
    "user": {"domain": "CORP", "name": "jdoe"},
    "source": {"ip": "10.10.10.21"},
    "winlog": {"event_data": {"LogonType": "3", "WorkstationName": "WS-0231", "AuthenticationPackageName": "Negotiate"}},
    "process": {"executable": r"C:\Windows\System32\svchost.exe"}
}

SERVICE_BATCH = {
    "event": {"code": 4624},
    "host": {"name": "APP-01"},
    "user": {"domain": "CORP", "name": "svc_backup"},
    "source": {"ip": "10.10.10.30"},
    "winlog": {"event_data": {"LogonType": "5", "WorkstationName": "APP-01", "AuthenticationPackageName": "Negotiate"}},
    "process": {"executable": r"C:\Windows\System32\services.exe"}
}

DEGRADED = {
    "event": {"code": 4624},
    "host": {"name": "FILE-01"},
    "user": {"domain": "CORP", "name": "administrator"},
    "winlog": {"event_data": {"LogonType": "10", "WorkstationName": "[MISSING]"}},
    "process": {"executable": r"C:\Windows\System32\svchost.exe"}
}

def main() -> None:
    cases = [
        ("PRIV_RDP", PRIV_RDP, "policies/windows_4624_privileged.policy.json"),
        ("SOC_NETWORK", SOC_NETWORK, "policies/windows_4624_soc.policy.json"),
        ("SERVICE_BATCH", SERVICE_BATCH, "policies/windows_4624_service_batch.policy.json"),
        ("DEGRADED", DEGRADED, "policies/windows_4624_privileged.policy.json"),
    ]

    for label, evt, pol in cases:
        res = evaluate_event(evt, kind="windows-4624", policy_path=pol)
        print(f"\n=== {label} ({res.policy.name}) ===")
        print(res.card.to_dict())

if __name__ == "__main__":
    main()
