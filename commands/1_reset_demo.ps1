# DetectForge — STEP 1: reset to the clean "before" state (T1078 = RED blind spot).
# Run this before EVERY demo recording.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "[1/3] Stopping any running API..." -ForegroundColor Cyan
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
  Where-Object { $_.CommandLine -like "*uvicorn*api.main*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

Write-Host "[2/3] Removing old detections + database..." -ForegroundColor Cyan
uv run python scripts/seed_baseline.py --remove | Select-Object -Last 1
Remove-Item detectforge.db -ErrorAction SilentlyContinue

Write-Host "[3/3] Installing fresh baseline (leaves T1078 + T1021 open)..." -ForegroundColor Cyan
uv run python scripts/seed_baseline.py | Select-Object -Last 1

Write-Host ""
Write-Host "Baseline reset: database cleared, 16 detections installed, T1078 + T1021 left open." -ForegroundColor Green
Write-Host "NOTE: the dashboards are NOT updated yet - the RED 60% state appears" -ForegroundColor Yellow
Write-Host "      only AFTER the scan in step 3 (the agent classifies the baseline then)." -ForegroundColor Yellow
Write-Host "Next: run 2_start_api.ps1, then 3_run_scan.ps1" -ForegroundColor Green
