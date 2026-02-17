# examples/run_4688_policy_card_demo.py
from dfs_core.explain import explain_score
from dfs_core.features.windows_4688 import win4688_to_inputs_and_flags
from dfs_core.guardrails import DFSGuardrail
from dfs_core.policy import load_policy
from dfs_core.decision_card import build_decision_card


FULL = {
    "event": {"code": 4688},
    "host": {"name": "WS-0231"},
    "user": {"name": "jdoe"},
    "process": {
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "name": "powershell.exe",
        "command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA...==",
        "parent": {"executable": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"},
    },
}

DEGRADED = {
    "event": {"code": 4688},
    "host": {"name": "WS-0231"},
    "user": {"name": "jdoe"},
    "process": {
        "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "name": "powershell.exe",
        "command_line": "[REDACTED_OR_MISSING]",
        "parent": {"executable": "[MISSING]"},
    },
    "winlog": {"event_data": {"CommandLine": "[REDACTED_OR_MISSING]", "CreatorProcessName": "[MISSING]"}},
}


def main() -> None:
    policy = load_policy("policies/default.policy.json")
    guard = DFSGuardrail(thresholds=policy.thresholds)

    for label, evt in [("FULL", FULL), ("DEGRADED", DEGRADED)]:
        inputs, flags = win4688_to_inputs_and_flags(evt)
        exp = explain_score(inputs, flags, weights=policy.weights, penalties=policy.penalties)
        decision = guard.decide(exp.final_score, inputs=inputs)

        card = build_decision_card(
            event_kind="windows-4688",
            explanation=exp,
            action=decision.action.value,
            rationale=decision.rationale,
            policy_name=policy.name,
            host=evt.get("host", {}).get("name"),
            user=evt.get("user", {}).get("name"),
        )

        print(f"\n=== {label} ===")
        print(card.to_dict())


if __name__ == "__main__":
    main()
