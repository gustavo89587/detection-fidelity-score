$root = Split-Path $PSScriptRoot -Parent
cd $root

python .\dfs_cli.py score .\examples\events_4104.jsonl --kind windows-powershell-4104 --policy .\policies\powershell_4104.policy.json --limit 3

python .\dfs_cli.py score .\data\sysmon_fixed.jsonl --kind windows-sysmon-1 --policy .\policies\sysmon_1.policy.json --limit 3

