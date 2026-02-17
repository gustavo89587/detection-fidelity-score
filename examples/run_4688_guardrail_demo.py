# examples/run_4688_guardrail_demo.py
from dfs_core import DFSModel
from dfs_core.guardrails import DFSGuardrail
from dfs_core.features.windows_4688 import win4688_to_dfs_inputs

FULL = {
    "event": {"code": 4688},
    "host": {"name": "WS-0231", "os": {"type": "windows"}},
    "user": {"domain": "CORP", "name": "jdoe"},
    "process": {
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "name": "powershell.exe",
        "command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA...==",
        "parent": {"executable": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"},
    },
}

DEGRADED = {
    "event": {"code": 4688},
    "host": {"name": "WS-0231", "os": {"type": "windows"}},
    "user": {"domain": "CORP", "name": "jdoe"},
    "process": {
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "name": "powershell.exe",
        "command_line": "[REDACTED_OR_MISSING]",
        "parent": {"executable": "[MISSING]"},
    },
}

def main() -> None:
    model = DFSModel()
    guard = DFSGuardrail()

    for label, evt in [("FULL", FULL), ("DEGRADED", DEGRADED)]:
        inputs = win4688_to_dfs_inputs(evt)
        score = model.score(inputs)
        decision = guard.decide(score, inputs=inputs)
        print(f"{label}: score={score:.3f} -> {decision.action.value} | {decision.rationale}")

if __name__ == "__main__":
    main()
