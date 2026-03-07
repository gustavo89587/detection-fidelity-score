# DFS Repo Cleanup Script
# Executa na raiz do repo: C:\Users\GUSTAVO\detection-fidelity-score
# Uso: powershell -ExecutionPolicy Bypass -File cleanup.ps1

Write-Host "`n=== DFS REPO CLEANUP ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. RAIZ — mover test_*_manual.py para tests/
# ---------------------------------------------------------------------------
Write-Host "`n[1] Movendo testes manuais para tests/" -ForegroundColor Yellow
$manualTests = @(
    "Test_4624_manual.py", "test_agent_manual.py", "test_azure_ad_manual.py",
    "test_cve_manual.py", "test_cyber_wall_manual.py", "test_docker_manual.py",
    "test_engine.py", "test_gcp_manual.py", "test_guardduty_manual.py",
    "test_infra_manual.py", "test_new_modules_manual.py", "test_siems_manual.py",
    "test_sysmon3_manual.py", "test_wifi_csi_manual.py"
)
foreach ($f in $manualTests) {
    if (Test-Path $f) {
        Move-Item $f "tests\" -Force
        Write-Host "  moved: $f -> tests/" -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# 2. RAIZ — mover scripts soltos para scripts/
# ---------------------------------------------------------------------------
Write-Host "`n[2] Movendo scripts para scripts/" -ForegroundColor Yellow
$scripts = @("dfs_cli.py", "dfs_score.py", "pipeline.py", "simulate.py", "windows_powershell_4104.py")
foreach ($f in $scripts) {
    if (Test-Path $f) {
        Move-Item $f "scripts\" -Force
        Write-Host "  moved: $f -> scripts/" -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# 3. RAIZ — mover dados soltos para data/
# ---------------------------------------------------------------------------
Write-Host "`n[3] Movendo dados para data/" -ForegroundColor Yellow
$dataFiles = @(
    "decision.json", "dfs_agent_timeline.csv", "dfs_calibration_report.csv",
    "dfs_monte_carlo_report.csv", "dfs_report.csv", "dfs_generated_files.txt"
)
foreach ($f in $dataFiles) {
    if (Test-Path $f) {
        Move-Item $f "data\" -Force
        Write-Host "  moved: $f -> data/" -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------
# 4. RAIZ — mover notebook para notebooks/
# ---------------------------------------------------------------------------
Write-Host "`n[4] Movendo notebook para notebooks/" -ForegroundColor Yellow
if (Test-Path "dfs_scoring_notebook.ipynb") {
    Move-Item "dfs_scoring_notebook.ipynb" "notebooks\" -Force
    Write-Host "  moved: dfs_scoring_notebook.ipynb -> notebooks/" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 5. RAIZ — deletar arquivos desnecessários
# ---------------------------------------------------------------------------
Write-Host "`n[5] Deletando arquivos desnecessários da raiz" -ForegroundColor Yellow
$toDelete = @("tests.yml", "signals.stage", "detection-fidelity-score.yaml")
foreach ($f in $toDelete) {
    if (Test-Path $f) {
        Remove-Item $f -Force
        Write-Host "  deleted: $f" -ForegroundColor Red
    }
}
if (Test-Path "__pycache__") {
    Remove-Item "__pycache__" -Recurse -Force
    Write-Host "  deleted: __pycache__" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 6. dfs_core/ — deletar arquivos claramente errados
# ---------------------------------------------------------------------------
Write-Host "`n[6] Limpando dfs_core/" -ForegroundColor Yellow
$coreDelete = @(
    "dfs_core\__init.py__.py",
    "dfs_core\dir.txt",
    "dfs_core\dfs_agent_timeline.csv"
)
foreach ($f in $coreDelete) {
    if (Test-Path $f) {
        Remove-Item $f -Force
        Write-Host "  deleted: $f" -ForegroundColor Red
    }
}
if (Test-Path "dfs_core\__pycache__") {
    Remove-Item "dfs_core\__pycache__" -Recurse -Force
    Write-Host "  deleted: dfs_core\__pycache__" -ForegroundColor Red
}
if (Test-Path "dfs_core\runs") {
    Remove-Item "dfs_core\runs" -Recurse -Force
    Write-Host "  deleted: dfs_core\runs\" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 7. dfs_core/ — arquivar suspeitos em _archive/
# ---------------------------------------------------------------------------
Write-Host "`n[7] Arquivando suspeitos em dfs_core/_archive/" -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "dfs_core\_archive" | Out-Null
$suspects = @(
    "guardrails.py", "decision_card.py", "engine.py", "evaluate.py",
    "dfs_ai.py", "dfs_ai_v2.py", "pipeline.py", "simulate.py",
    "policy.py", "io.py", "stream.py", "explain.py", "agent_pipeline_sim.py"
)
foreach ($f in $suspects) {
    $src = "dfs_core\$f"
    if (Test-Path $src) {
        Move-Item $src "dfs_core\_archive\" -Force
        Write-Host "  archived: $f -> dfs_core/_archive/" -ForegroundColor DarkYellow
    }
}

# ---------------------------------------------------------------------------
# 8. .gitignore — garantir que _archive e __pycache__ estão ignorados
# ---------------------------------------------------------------------------
Write-Host "`n[8] Verificando .gitignore" -ForegroundColor Yellow
$gitignore = Get-Content ".gitignore" -ErrorAction SilentlyContinue
if ($gitignore -notcontains "_archive/") {
    Add-Content ".gitignore" "`n# Archived files`n_archive/"
    Write-Host "  added _archive/ to .gitignore" -ForegroundColor Green
}
if ($gitignore -notcontains "__pycache__/") {
    Add-Content ".gitignore" "`n__pycache__/"
    Write-Host "  added __pycache__/ to .gitignore" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 9. Commit
# ---------------------------------------------------------------------------
Write-Host "`n[9] Commit" -ForegroundColor Yellow
git add -A
git commit -m "chore: repo cleanup — move tests, scripts, data; archive suspects; remove clutter"
git push origin main

Write-Host "`n=== CLEANUP COMPLETE ===" -ForegroundColor Cyan
Write-Host "Suspeitos preservados em dfs_core/_archive/ — delete em 30 dias se nao precisar." -ForegroundColor White
