# examples/run_sysmon1_demo.py
from dfs_core.pipeline import evaluate_event

FULL = {
    "event": {"code": 1},
    "host": {"name": "WS-0231"},
    "user": {"name": "jdoe"},
    "process": {
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA...==",
        "parent": {
            "executable": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "command_line": r"WINWORD.EXE /n C:\Users\jdoe\Downloads\invoice.docm"
        }
    },
    "winlog": {
        "event_data": {
            "Hashes": "SHA256=deadbeef...",
            "IntegrityLevel": "Medium",
            "LogonId": "0x3e7"
        }
    }
}

DEGRADED = {
    "event": {"code": 1},
    "host": {"name": "WS-0231"},
    "user": {"name": "jdoe"},
    "process": {
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "[REDACTED_OR_MISSING]",
        "parent": {"executable": "[MISSING]", "command_line": "[MISSING]"}
    },
    "winlog": {"event_data": {"Hashes": "[MISSING]"}}
}

def main() -> None:
    for label, evt in [("FULL", FULL), ("DEGRADED", DEGRADED)]:
        res = evaluate_event(
            evt,
            kind="windows-sysmon-1",
            policy_path="policies/sysmon_1.policy.json"
        )
        print(f"\n=== {label} ===")
        print(res.card.to_dict())

if __name__ == "__main__":
    main()
