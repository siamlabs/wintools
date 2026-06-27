# test-sandbox.ps1
# Quick smoke test for Windows Sandbox
# Run this INSIDE Windows Sandbox after copying sys-mon files there
# Usage: powershell -ExecutionPolicy Bypass -File test-sandbox.ps1

$ErrorActionPreference = "Stop"
$PassCount = 0
$FailCount = 0

function Test-Step {
    param([string]$Name, [scriptblock]$Test)
    Write-Host "`n[TEST] $Name" -ForegroundColor Cyan
    try {
        & $Test
        Write-Host "  PASS" -ForegroundColor Green
        $script:PassCount++
    }
    catch {
        Write-Host "  FAIL: $_" -ForegroundColor Red
        $script:FailCount++
    }
}

Write-Host "========================================" -ForegroundColor White
Write-Host "  sys-mon Windows Sandbox Smoke Test" -ForegroundColor White
Write-Host "========================================" -ForegroundColor White

Test-Step "sys-mon.exe exists" -Test {
    if (-not (Test-Path ".\sys-mon.exe")) { throw "Not found" }
    $f = Get-Item ".\sys-mon.exe"
    Write-Host "  $([math]::Round($f.Length/1MB,1)) MB"
}

Test-Step "sys-mon-panel.exe exists" -Test {
    if (-not (Test-Path ".\sys-mon-panel.exe")) { throw "Not found" }
    $f = Get-Item ".\sys-mon-panel.exe"
    Write-Host "  $([math]::Round($f.Length/1MB,1)) MB"
}

Test-Step "CLI --version" -Test {
    $out = .\sys-mon.exe --version 2>&1
    if ($out -notmatch "sys-mon 0\.1\.0") { throw "Unexpected: $out" }
    Write-Host "  $out"
}

Test-Step "CLI baseline save" -Test {
    $out = .\sys-mon.exe baseline save sandbox 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Exit code: $LASTEXITCODE, output: $out" }
    Write-Host "  $out"
    $json = Get-Content "config\baselines\sandbox.json" -Raw | ConvertFrom-Json
    if ($json.ports.Count -eq 0) { throw "No ports captured" }
    Write-Host "  Ports captured: $($json.ports.Count)"
}

Test-Step "CLI baseline list" -Test {
    $out = .\sys-mon.exe baseline list 2>&1
    if ($out -notmatch "sandbox") { throw "Missing 'sandbox' in output: $out" }
    Write-Host "  $out"
}

Test-Step "CLI ports check (same baseline)" -Test {
    $out = .\sys-mon.exe ports check sandbox 2>&1
    if ($out -notmatch "No anomalies") {
        Write-Host "  Note: $out" -ForegroundColor Yellow
    } else {
        Write-Host "  $out"
    }
}

Test-Step "CLI ports check (missing baseline)" -Test {
    $out = .\sys-mon.exe ports check nonexistent 2>&1
    if ($out -notmatch "Error loading baseline") { throw "Expected error, got: $out" }
    Write-Host "  Correctly reports missing baseline"
}

Test-Step "CLI ports list" -Test {
    $out = .\sys-mon.exe ports list 2>&1
    $count = [int]($out -match "Total:\s+(\d+)" | ForEach-Object { $matches[1] })
    if ($count -eq 0) { throw "No ports found" }
    Write-Host "  Found $count ports"
}

Test-Step "CLI baseline delete" -Test {
    $out = .\sys-mon.exe baseline delete sandbox 2>&1
    if ($out -notmatch "deleted") { throw "Unexpected: $out" }
    Write-Host "  $out"
    if (Test-Path "config\baselines\sandbox.json") { throw "File still exists" }
    Write-Host "  File removed"
}

Test-Step "Panel binary runs" -Test {
    $proc = Start-Process -FilePath ".\sys-mon-panel.exe" -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3
    if ($proc.HasExited) {
        throw "Exited immediately (code: $($proc.ExitCode))"
    }
    Stop-Process -Id $proc.Id -Force
    Write-Host "  Ran 3s without crash"
}

Write-Host "`n========================================" -ForegroundColor White
Write-Host "  Results: $PassCount passed, $FailCount failed" -ForegroundColor $(if ($FailCount -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor White

if ($FailCount -gt 0) {
    Write-Host "`nSome tests failed. Check output above." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll smoke tests passed! Ready for full VM test." -ForegroundColor Green
    exit 0
}
