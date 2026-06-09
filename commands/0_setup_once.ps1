# DetectForge — ONE-TIME setup (run once before your first demo).
# Installs the 5 Splunk dashboards. (HEC + index are already configured.)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "Installing DetectForge dashboards into Splunk..." -ForegroundColor Cyan
uv run python dashboard/setup_dashboards.py

Write-Host ""
Write-Host "Done. Dashboards installed. Next: run 1_reset_demo.ps1" -ForegroundColor Green
