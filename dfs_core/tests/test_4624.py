# dfs-core/tests/test_4624.py
from dfs_core.pipeline import evaluate_event


def test_4624_privileged_has_higher_score_than_degraded():
    privileged = {
        "event": {"code": 4624},
        "host": {"name": "DC-01"},
        "user": {"domain": "CORP", "name": "administrator"},
        "source": {"ip": "198.51.100.50"},
        "winlog": {"event_data": {"LogonType": "10", "WorkstationName": "WS-091", "AuthenticationPackageName": "Negotiate"}},
        "process": {"executable": r"C:\Windows\System32\svchost.exe"}
    }

    degraded = {
        "event": {"code": 4624},
        "host": {"name": "DC-01"},
        "user": {"domain": "CORP", "name": "administrator"},
        "winlog": {"event_data": {"LogonType": "10", "WorkstationName": "[MISSING]"}},
        "process": {"executable": r"C:\Windows\System32\svchost.exe"}
    }

    r1 = evaluate_event(privileged, kind="windows-4624", policy_path="policies/windows_4624_privileged.policy.json")
    r2 = evaluate_event(degraded, kind="windows-4624", policy_path="policies/windows_4624_privileged.policy.json")

    assert r1.card.score > r2.card.score
