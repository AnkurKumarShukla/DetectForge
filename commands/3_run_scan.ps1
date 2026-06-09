# DetectForge — STEP 3: run the agent scan, wait until detections are queued.
# Run this in a NEW terminal (while 2_start_api.ps1 keeps running).
$ErrorActionPreference = "Stop"
$api = "http://127.0.0.1:8077"

Write-Host "Triggering agent scan (healthcare)..." -ForegroundColor Cyan
$r = Invoke-RestMethod "$api/api/v1/scan" -Method Post -Body '{"industry":"healthcare","max_gaps":5}' -ContentType "application/json"
$sid = $r.scan_id
Write-Host "Scan started: $sid" -ForegroundColor Green
Write-Host "Watch it live in the control panel + Agent Activity dashboard." -ForegroundColor Yellow

for ($i = 0; $i -lt 45; $i++) {
    Start-Sleep -Seconds 8
    try {
        $s = Invoke-RestMethod "$api/api/v1/scan/$sid/status"
        Write-Host ("  [{0}] {1}  queued={2}" -f $i, $s.status, $s.rules_queued_for_review)
        if ($s.status -eq "complete" -or $s.status -eq "error") { break }
    } catch { }
}

Write-Host ""
$q = Invoke-RestMethod "$api/api/v1/review/queue"
Write-Host ("Scan done. {0} detections queued for review (T1078 family)." -f $q.Count) -ForegroundColor Green
Write-Host "Now: open the Attack Path dashboard (T1078 = RED), then approve T1078 on the panel." -ForegroundColor Green
