# setup-win11-vm.ps1
# Creates a Hyper-V VM for sys-mon post-release testing
# Run as Administrator
# Usage: powershell -ExecutionPolicy Bypass -File setup-win11-vm.ps1

$ErrorActionPreference = "Stop"

$VMName = "sys-mon-test"
$VMMemory = 4GB
$VMDiskSize = 64GB
$VMDiskPath = "C:\Hyper-V\$VMName\$VMName.vhdx"
$VMDvdPath = "C:\Hyper-V\$VMName\$VMName-dvd.iso"
$ISOPath = ""  # Set this to your Win11 ISO path

# ============================================================
# Pre-flight checks
# ============================================================
Write-Host "Pre-flight checks..." -ForegroundColor Cyan

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Must run as Administrator" -ForegroundColor Red
    exit 1
}

# Check Hyper-V
$hvModule = Get-Module -ListAvailable Hyper-V
if (-not $hvModule) {
    Write-Host "ERROR: Hyper-V module not installed." -ForegroundColor Red
    Write-Host "Install with: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All" -ForegroundColor Yellow
    exit 1
}

$hvSwitch = Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object { $_.SwitchType -eq "External" }
if (-not $hvSwitch) {
    Write-Host "ERROR: No external virtual switch found." -ForegroundColor Red
    Write-Host "Create one in Hyper-V Manager or run:" -ForegroundColor Yellow
    Write-Host "  New-VMSwitch -Name 'External' -NetAdapterName '<your-nic>' -AllowManagementScript \$true" -ForegroundColor Yellow
    exit 1
}
Write-Host "  Hyper-V: OK" -ForegroundColor Green
Write-Host "  External switch: $($hvSwitch.Name)" -ForegroundColor Green

# Check ISO
if (-not $ISOPath) {
    $ISOPath = Read-Host "Path to Windows 11 ISO (e.g., C:\ISOs\Win11_24H2.iso)"
}
if (-not (Test-Path $ISOPath)) {
    Write-Host "ERROR: ISO not found at $ISOPath" -ForegroundColor Red
    exit 1
}
Write-Host "  ISO: $ISOPath" -ForegroundColor Green

# ============================================================
# Create VM
# ============================================================
Write-Host "`nCreating VM '$VMName'..." -ForegroundColor Cyan

$vmDir = "C:\Hyper-V\$VMName"
New-Item -ItemType Directory -Path $vmDir -Force | Out-Null

# Generation 2 = UEFI + Secure Boot (required for Win11)
New-VM -Name $VMName `
    -MemoryStartupBytes $VMMemory `
    -NewVHDPath $VMDiskPath `
    -NewVHDSizeBytes $VMDiskSize `
    -Generation 2 `
    -SwitchName $hvSwitch.Name | Out-Null

# Copy ISO to VM directory for easy access
Copy-Item $ISOPath $VMDvdPath -Force

# DVD drive
Add-VMDvdDrive -VMName $VMName -Path $VMDvdPath

# Processor
Set-VMProcessor -VMName $VMName -Count 4

# Enable Secure Boot
Set-VMFirmware -VMName $VMName -EnableSecureBoot On `
    -SecureBootTemplate "MicrosoftUEFI2"

# Enable checkpoint
Set-VM -VMName $VMName -CheckpointType Standard

# VMCX settings for Win11
Set-VM -VMName $VMName -CompatibilityForMigration 0
Set-VM -VMName $VMName -LowMemoryMappedIoSpace 3GB `
    -HighMemoryMappedIoSpace 128GB `
    -MemoryStandbyBufferPercentage 110 `
    -AutomaticStopAction Shutdown

Write-Host "`nVM created successfully!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Open Hyper-V Manager (hyper-v.msc)" -ForegroundColor White
Write-Host "  2. Select '$VMName' and click 'Connect'" -ForegroundColor White
Write-Host "  3. Install Windows 11 from the DVD" -ForegroundColor White
Write-Host "  4. After install, copy sys-mon-0.1.0-win64.zip into the VM" -ForegroundColor White
Write-Host "  5. Run: tests\test-release.ps1" -ForegroundColor White
Write-Host "  6. When done, delete the VM to free 64GB" -ForegroundColor White
Write-Host "`n  Delete VM: Remove-VM -Name '$VMName' -Delete`" -ForegroundColor Yellow
