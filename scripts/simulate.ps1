param(
  [Parameter(Mandatory=True)][string]
)

New-Item -ItemType Directory -Force -Path output | Out-Null

py -m cli.dfs simulate --scenario  --out ("output/{0}.csv" -f )

Write-Host ("Done -> output/{0}.csv" -f )
