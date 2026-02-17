# dfs-core/tests/test_explainable_scoring.py
from dfs_core.explain import explain_score
from dfs_core.features.windows_4688 import win4688_to_inputs_and_flags


def test_explainable_scoring_penalizes_missing_context():
    full = {
        "event": {"code": 4688},
        "host": {"name": "WS-0231"},
        "user": {"name": "jdoe"},
        "process": {
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA...==",
            "parent": {"executable": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"},
        },
    }

    degraded = {
        "event": {"code": 4688},
        "host": {"name": "WS-0231"},
        "user": {"name": "jdoe"},
        "process": {
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "[REDACTED_OR_MISSING]",
            "parent": {"executable": "[MISSING]"},
        },
        "winlog": {"event_data": {"CommandLine": "[REDACTED_OR_MISSING]", "CreatorProcessName": "[MISSING]"}},
    }

    full_inputs, full_flags = win4688_to_inputs_and_flags(full)
    deg_inputs, deg_flags = win4688_to_inputs_and_flags(degraded)

    full_exp = explain_score(full_inputs, full_flags)
    deg_exp = explain_score(deg_inputs, deg_flags)

    assert full_exp.final_score > deg_exp.final_score
    assert any(name == "missing_command_line" for name, _ in deg_exp.penalties_applied)
    assert any(name == "missing_parent" for name, _ in deg_exp.penalties_applied)
