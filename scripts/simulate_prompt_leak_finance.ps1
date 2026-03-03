New-Item -ItemType Directory -Force -Path output | Out-Null

py -m cli.dfs simulate --scenario prompt_leak_finance --out output/prompt_leak_finance.csv

Write-Host "Done -> output/prompt_leak_finance.csv"
