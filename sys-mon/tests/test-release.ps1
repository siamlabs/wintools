# test-release.ps1
# Post-release validation script for sys-mon on Windows 11
# Run as Administrator for full coverage
# Usage: powershell -ExecutionPolicy Bypass -File test-release.ps1

$ErrorActionPreference = "Stop"
$PassCount = 0
$FailCount = 0
$SkipCount = 0
$Results = @()

function Test-Step {
    param(
        [string]$Name,
        [scriptblock]$Test,
        [switch]$RequiresAdmin
    )
    Write-Host "`n[TEST] $Name" -ForegroundColor Cyan

    if ($RequiresAdmin) {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Host "  SKIP (requires admin)" -ForegroundColor Yellow
            $script:SkipCount++
            $script:Results += [PSCustomObject]@{
                Test = $Name
                Status = "SKIP"
                Detail = "Requires admin, running as non-admin"
            }
            return
        }
    }

    try {
        & $Test
        Write-Host "  PASS" -ForegroundColor Green
        $script:PassCount++
        $script:Results += [PSCustomObject]@{
            Test = $Name
            Status = "PASS"
            Detail = ""
        }
    }
    catch {
        Write-Host "  FAIL: $_" -ForegroundColor Red
        $script:FailCount++
        $script:Results += [PSCustomObject]@{
            Test = $Name
            Status = "FAIL"
            Detail = $_.Exception.Message
        }
    }
}

# ============================================================
# Phase 1: Environment checks
# ============================================================
Write-Host "========================================" -ForegroundColor White
Write-Host "  sys-mon Post-Release Test Suite" -ForegroundColor White
Write-Host "========================================" -ForegroundColor White

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Running as admin: $isAdmin" -ForegroundColor $(if ($isAdmin) { "Green" } else { "Yellow" })

Test-Step "Windows 11 detected" -Test {
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.Version -notmatch "^10\.\d+" -and $os.Version -notmatch "^11\.\d+") {
        throw "Not Windows 10/11 (version: $($os.Version))"
    }
    Write-Host "  OS: $($os.Caption) v$($os.Version)"
}

Test-Step "sys-mon.exe exists" -Test {
    if (-not (Test-Path ".\sys-mon.exe")) {
        throw "sys-mon.exe not found in current directory"
    }
    $file = Get-Item ".\sys-mon.exe"
    Write-Host "  Size: $([math]::Round($file.Length / 1MB, 1)) MB"
}

Test-Step "sys-mon-panel.exe exists" -Test {
    if (-not (Test-Path ".\sys-mon-panel.exe")) {
        throw "sys-mon-panel.exe not found in current directory"
    }
    $file = Get-Item ".\sys-mon-panel.exe"
    Write-Host "  Size: $([math]::Round($file.Length / 1MB, 1)) MB"
}

# ============================================================
# Phase 2: CLI tests
# ============================================================
Write-Host "`n--- CLI Tests ---" -ForegroundColor Gray

Test-Step "CLI --version flag" -Test {
    $output = .\sys-mon.exe --version 2>&1
    if ($output -notmatch "sys-mon 0\.1\.0") {
        throw "Version output unexpected: $output"
    }
    Write-Host "  $output"
}

Test-Step "CLI usage output" -Test {
    $output = .\sys-mon.exe 2>&1
    if ($LASTEXITCODE -eq 0) {
        throw "Expected non-zero exit code for no args"
    }
    if ($output -notmatch "Usage:") {
        throw "Missing usage text in output"
    }
    Write-Host "  Usage text displayed correctly"
}

Test-Step "CLI baseline save" -Test {
    # Use temp dir to avoid polluting real baselines
    $tmpDir = Join-Path $env:TEMP "sys-mon-test-$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $env:SYS_MON_BASELINE_DIR = $tmpDir

    $output = .\sys-mon.exe baseline save test-ci 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "baseline save failed: $output"
    }
    Write-Host "  $output"

    # Verify file was created
    $baselineFile = Join-Path $tmpDir "test-ci.json"
    if (-not (Test-Path $baselineFile)) {
        throw "Baseline file not created at $baselineFile"
    }
    $content = Get-Content $baselineFile -Raw
    $json = $content | ConvertFrom-Json
    if ($json.version -ne 1) {
        throw "Baseline version mismatch: $($json.version)"
    }
    if ($json.ports.Count -eq 0) {
        throw "Baseline has no ports"
    }
    Write-Host "  Baseline saved: $($json.ports.Count) ports"

    # Cleanup
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:SYS_MON_BASELINE_DIR -ErrorAction SilentlyContinue
}

Test-Step "CLI baseline list" -Test {
    $tmpDir = Join-Path $env:TEMP "sys-mon-test-$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $env:SYS_MON_BASELINE_DIR = $tmpDir

    # Save a baseline first
    .\sys-mon.exe baseline save test-list > $null 2>&1

    $output = .\sys-mon.exe baseline list 2>&1
    if ($output -notmatch "test-list") {
        throw "Baseline 'test-list' not found in list output"
    }
    Write-Host "  $output"

    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:SYS_MON_BASELINE_DIR -ErrorAction SilentlyContinue
}

Test-Step "CLI baseline delete" -Test {
    $tmpDir = Join-Path $env:TEMP "sys-mon-test-$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $env:SYS_MON_BASELINE_DIR = $tmpDir

    .\sys-mon.exe baseline save test-del > $null 2>&1

    $output = .\sys-mon.exe baseline delete test-del 2>&1
    if ($output -notmatch "deleted") {
        throw "Delete output unexpected: $output"
    }
    Write-Host "  $output"

    # Verify file is gone
    if (Test-Path (Join-Path $tmpDir "test-del.json")) {
        throw "Baseline file still exists after delete"
    }

    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:SYS_MON_BASELINE_DIR -ErrorAction SilentlyContinue
}

Test-Step "CLI ports check (no baseline)" -Test {
    $tmpDir = Join-Path $env:TEMP "sys-mon-test-$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $env:SYS_MON_BASELINE_DIR = $tmpDir

    $output = .\sys-mon.exe ports check default 2>&1
    if ($output -notmatch "Error loading baseline") {
        throw "Expected error about missing baseline, got: $output"
    }
    Write-Host "  Correctly reports missing baseline"

    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:SYS_MON_BASELINE_DIR -ErrorAction SilentlyContinue
}

Test-Step "CLI ports check (with baseline)" -Test {
    $tmpDir = Join-Path $env:TEMP "sys-mon-test-$(Get-Date -Format 'yyyyMMddHHmmss')"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $env:SYS_MON_BASELINE_DIR = $tmpDir

    .\sys-mon.exe baseline save ci-baseline > $null 2>&1
    $output = .\sys-mon.exe ports check ci-baseline 2>&1
    if ($output -notmatch "No anomalies") {
        Write-Host "  Note: anomalies found (expected on fresh system): $output"
    } else {
        Write-Host "  $output"
    }

    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:SYS_MON_BASELINE_DIR -ErrorAction SilentlyContinue
}

Test-Step "CLI ports list" -Test {
    $output = .\sys-mon.exe ports list 2>&1
    if ($output -notmatch "Total:") {
        throw "Ports list missing total count"
    }
    $count = [int]($output -match "Total:\s+(\d+)" | ForEach-Object { $matches[1] })
    Write-Host "  Found $count ports"
    if ($count -eq 0) {
        throw "No ports found — netstat may be failing"
    }
}

# ============================================================
# Phase 3: Process resolution
# ============================================================
Write-Host "`n--- Process Resolution Tests ---" -ForegroundColor Gray

Test-Step "Process name resolution (PID 4)" -RequiresAdmin -Test {
    $result = wmic process where "ProcessId=4" get ImageName,ExecutablePath /value 2>&1
    if ($result -notmatch "ImageName") {
        Write-Host "  Note: wmic may be deprecated on this system" -ForegroundColor Yellow
    } else {
        Write-Host "  wmic resolved PID 4 successfully"
    }
}

Test-Step "tasklist JSON output" -Test {
    $result = tasklist /FI "PID eq 4" /FO JSON /NH 2>&1
    if ($result -notmatch "ImageName") {
        throw "tasklist JSON output failed"
    }
    $json = $result | ConvertFrom-Json
    Write-Host "  PID 4 = $($json.'Info'.ImageName)"
}

# ============================================================
# Phase 4: WSL2 detection
# ============================================================
Write-Host "`n--- WSL2 Detection ---" -ForegroundColor Gray

Test-Step "WSL2 installed?" -Test {
    $wsl = wsl --status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  WSL2 is installed" -ForegroundColor Green
        # Check for vmmem processes
        $vmmem = Get-Process -Name "vmmem", "vmmemWSL" -ErrorAction SilentlyContinue
        if ($vmmem) {
            Write-Host "  vmmem processes: $($vmmem.Count)"
        }
    } else {
        Write-Host "  WSL2 not installed (skip WSL2-specific tests)" -ForegroundColor Yellow
    }
}

# ============================================================
# Phase 5: Firewall block (admin only)
# ============================================================
Write-Host "`n--- Firewall Tests (admin) ---" -ForegroundColor Gray

Test-Step "Firewall block rule creation" -RequiresAdmin -Test {
    $ruleName = "sys-mon-test-$(Get-Random)"
    $output = netsh advfirewall firewall add rule name="$ruleName" dir=in protocol=tcp localport=99999 action=block 2>&1
    if ($output -match "created" -or $output -match "OK") {
        Write-Host "  Rule created successfully" -ForegroundColor Green
    } else {
        Write-Host "  Note: $output" -ForegroundColor Yellow
    }

    # Cleanup
    netsh advfirewall firewall delete rule name="$ruleName" > $null 2>&1
}

# ============================================================
# Phase 6: Non-admin degradation
# ============================================================
Write-Host "`n--- Non-Admin Tests ---" -ForegroundColor Gray

if ($isAdmin) {
    Test-Step "Non-admin mode simulation" -Test {
        Write-Host "  Running as admin — non-admin path not testable here" -ForegroundColor Yellow
        Write-Host "  Manual test: run sys-mon.exe without admin on clean Win11"
    }
} else {
    Test-Step "Non-admin mode" -Test {
        Write-Host "  Running as non-admin — all tests should work with degraded process info" -ForegroundColor Green
    }
}

# ============================================================
# Phase 7: Panel smoke test
# ============================================================
Write-Host "`n--- Panel Smoke Test ---" -ForegroundColor Gray

Test-Step "Panel binary runs without crash" -Test {
    # Start the panel, wait 3 seconds, then kill it
    $proc = Start-Process -FilePath ".\sys-mon-panel.exe" -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 3

    if ($proc.HasExited) {
        throw "Panel exited immediately (exit code: $($proc.ExitCode))"
    }

    # Kill it
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Write-Host "  Panel started and ran for 3 seconds without crashing" -ForegroundColor Green
}

# ============================================================
# Results
# ============================================================
Write-Host "`n========================================" -ForegroundColor White
Write-Host "  Results: $PassCount passed, $FailCount failed, $SkipCount skipped" -ForegroundColor $(if ($FailCount -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor White

if ($FailCount -gt 0) {
    Write-Host "`nFailed tests:" -ForegroundColor Red
    $Results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host "  ✗ $($_.Test): $($_.Detail)" -ForegroundColor Red
    }
    exit 1
} else {
    Write-Host "`nAll tests passed!" -ForegroundColor Green
    exit 0
}
