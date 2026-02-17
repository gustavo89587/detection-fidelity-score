# examples/run_4688_explainable_demo.py
from dfs_core.explain import explain_score
from dfs_core.guardrails import DFSGuardrail
from dfs_core.features.windows_4688 import win4688_to_inputs_and_flags

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

def render(label: str, exp) -> None:
    print(f"\n=== {label} ===")
    print(f"inputs: S={exp.inputs.s:.2f} T={exp.inputs.t:.2f} B={exp.inputs.b:.2f}")
    print(f"base_score:  {exp.base_score:.3f}")
    if exp.penalties_applied:
        print("penalties:")
        for name, p in exp.penalties_applied:
            print(f"  - {name}: {p:.2f}")
    else:
        print("penalties: none")
    print(f"final_score: {exp.final_score:.3f}")
    for n in exp.notes:
        print(f"- {n}")

def main() -> None:
    guard = DFSGuardrail()

    for label, evt in [("FULL", FULL), ("DEGRADED", DEGRADED)]:
        inputs, flags = win4688_to_inputs_and_flags(evt)
        exp = explain_score(inputs, flags)
        decision = guard.decide(exp.final_score, inputs=inputs)
        render(label, exp)
        print(f"guardrail: {decision.action.value}")

if __name__ == "__main__":
    main()
