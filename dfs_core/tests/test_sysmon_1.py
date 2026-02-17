# dfs-core/tests/test_sysmon_1.py
from dfs_core.pipeline import evaluate_event


def test_sysmon1_full_scores_higher_than_degraded():
    full = {
        "host": {"name": "WS-0231"},
        "user": {"name": "jdoe"},
        "process": {
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA...==",
            "parent": {
                "executable": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "command_line": r"WINWORD.EXE /n invoice.docm"
            }
        },
        "winlog": {"event_data": {"Hashes": "SHA256=deadbeef", "IntegrityLevel": "Medium", "LogonId": "0x3e7"}}
    }

    degraded = {
        "host": {"name": "WS-0231"},
        "user": {"name": "jdoe"},
        "process": {
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "[REDACTED_OR_MISSING]",
            "parent": {"executable": "[MISSING]", "command_line": "[MISSING]"}
        },
        "winlog": {"event_data": {"Hashes": "[MISSING]"}}
    }

    r1 = evaluate_event(full, kind="windows-sysmon-1", policy_path="policies/sysmon_1.policy.json")
    r2 = evaluate_event(degraded, kind="windows-sysmon-1", policy_path="policies/sysmon_1.policy.json")

    assert r1.card.score > r2.card.score
