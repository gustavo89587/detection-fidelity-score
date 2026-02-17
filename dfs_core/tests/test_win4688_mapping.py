# dfs-core/tests/test_win4688_mapping.py
from dfs_core.features.windows_4688 import win4688_to_dfs_inputs
from dfs_core import DFSModel


def test_win4688_full_context_scores_higher_than_degraded():
    full = {
        "event": {"code": 4688},
        "host": {"name": "WS-0231", "os": {"type": "windows"}},
        "user": {"domain": "CORP", "name": "jdoe"},
        "process": {
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "name": "powershell.exe",
            "command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA...==",
            "parent": {
                "executable": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "name": "WINWORD.EXE",
                "command_line": r"WINWORD.EXE /n C:\Users\jdoe\Downloads\invoice.docm",
            },
        },
        "winlog": {"event_data": {"TokenElevationType": "%%1938"}},
    }

    degraded = {
        "event": {"code": 4688},
        "host": {"name": "WS-0231", "os": {"type": "windows"}},
        "user": {"domain": "CORP", "name": "jdoe"},
        "process": {
            "executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "name": "powershell.exe",
            "command_line": "[REDACTED_OR_MISSING]",
            "parent": {"executable": "[MISSING]"},
        },
        "winlog": {"event_data": {"CommandLine": "[REDACTED_OR_MISSING]", "CreatorProcessName": "[MISSING]"}},
    }

    model = DFSModel()

    full_inputs = win4688_to_dfs_inputs(full)
    degraded_inputs = win4688_to_dfs_inputs(degraded)

    full_score = model.score(full_inputs)
    degraded_score = model.score(degraded_inputs)

    assert full_score > degraded_score
