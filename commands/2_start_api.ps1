# DetectForge — STEP 2: start the API + control panel.
# Leave this window running. The control panel is at http://127.0.0.1:8077/
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "Starting DetectForge API on http://127.0.0.1:8077 ..." -ForegroundColor Cyan
Write-Host "Control panel:   http://127.0.0.1:8077/" -ForegroundColor Green
Write-Host "Splunk web:      http://localhost:8000" -ForegroundColor Green
Write-Host "(Keep this window open. Open a NEW terminal and run 3_run_scan.ps1)" -ForegroundColor Yellow
Write-Host ""
uv run uvicorn api.main:app --host 127.0.0.1 --port 8077
