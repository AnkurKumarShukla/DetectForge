# Run this script as Administrator in PowerShell
# Installs BOTS v3 pre-indexed data into Splunk and restarts the service

$SPLUNK_HOME = "C:\Program Files\Splunk"
$SPLUNK_APPS = "$SPLUNK_HOME\etc\apps"
$DATA_DIR    = "$PSScriptRoot"
$TGZ_FILE    = "$DATA_DIR\botsv3_data_set.tgz"
$EXTRACT_DIR = "$DATA_DIR\botsv3_extracted"

if (-not (Test-Path $TGZ_FILE)) {
    Write-Error "botsv3_data_set.tgz not found in $DATA_DIR"
    exit 1
}

Write-Host "Extracting BOTS v3..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force $EXTRACT_DIR | Out-Null
tar -xzf $TGZ_FILE -C $EXTRACT_DIR
Write-Host "Extraction complete." -ForegroundColor Green

Write-Host "Listing extracted contents..."
Get-ChildItem $EXTRACT_DIR -Depth 1 | Select-Object Name, Length

# The extracted folder is typically named 'botsv3' or similar
$extracted = Get-ChildItem $EXTRACT_DIR -Directory | Select-Object -First 1
if ($extracted) {
    $destApp = "$SPLUNK_APPS\$($extracted.Name)"
    Write-Host "Copying $($extracted.Name) → $destApp" -ForegroundColor Cyan
    Copy-Item -Path $extracted.FullName -Destination $destApp -Recurse -Force
    Write-Host "Copied." -ForegroundColor Green
} else {
    Write-Host "Copying all extracted content to $SPLUNK_APPS\botsv3" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force "$SPLUNK_APPS\botsv3" | Out-Null
    Copy-Item -Path "$EXTRACT_DIR\*" -Destination "$SPLUNK_APPS\botsv3" -Recurse -Force
    Write-Host "Copied." -ForegroundColor Green
}

Write-Host "Restarting Splunk..." -ForegroundColor Cyan
Restart-Service Splunkd -Force
Start-Sleep -Seconds 10

$status = (Get-Service Splunkd).Status
Write-Host "Splunk status: $status" -ForegroundColor Green
Write-Host ""
Write-Host "Done! Test with: index=botsv3 earliest=0 | head 5" -ForegroundColor Yellow
