# Post-Release Test Suite

Scripts for validating sys-mon on a clean Windows 11 installation.

## Test Tiers

### Tier 1: Windows Sandbox (Quick Smoke Test)
**Time:** ~10 minutes | **Setup:** Minimal

1. Enable Windows Sandbox (Pro/Enterprise):
   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientFramework"
   ```
2. Launch: `sandbox` or search "Windows Sandbox" in Start
3. Copy `sys-mon-0.1.0-win64.zip` contents into the sandbox
4. Run: `powershell -ExecutionPolicy Bypass -File test-sandbox.ps1`

**Catches:** Missing DLLs, path issues, basic CLI functionality, panel startup crash.

**Limitations:** Ephemeral (can't test baseline persistence), no admin testing.

---

### Tier 2: Full VM Test (Complete Validation)
**Time:** ~45 minutes | **Setup:** Hyper-V or VirtualBox

#### Option A: Hyper-V (Windows Pro/Enterprise)

1. Run `setup-win11-vm.ps1` as Administrator on your host
2. Install Windows 11 in the VM from the attached ISO
3. Copy `sys-mon-0.1.0-win64.zip` into the VM
4. Run `test-release.ps1` as Administrator inside the VM

```powershell
# Clean up when done
Remove-VM -Name "sys-mon-test" -Delete
```

#### Option B: VirtualBox (Free, works on Home edition)

1. Download [Windows 11 ISO](https://www.microsoft.com/software-download/windows11)
2. Create VM: 2 vCPUs, 4GB RAM, 64GB VDI, EFI enabled
3. Attach ISO, install Win11
4. Copy zip, run `test-release.ps1`

---

## What Each Test Checks

| Tier | Coverage |
|------|----------|
| **Sandbox** | Binary exists, CLI works, baseline save/list/delete, panel starts |
| **Full VM** | Everything above + admin operations, firewall rules, process resolution, WSL2 detection, non-admin degradation |

## Pass Criteria

All tests must pass before releasing to users. Any failure means:
- **CLI test failure** → build issue, missing dependency, or logic bug
- **Panel crash** → missing DLL, WebView2 not available, or Wails build issue
- **Baseline I/O failure** → path resolution or permissions issue
- **Process resolution failure** → wmic/tasklist not available on target system

## Manual Checklist (for full VM)

After automated tests pass, also verify manually:

- [ ] Tray icon appears with correct color
- [ ] Right-click tray menu works (Open Panel, Scan Now, Exit)
- [ ] Panel opens and shows ports/anomalies
- [ ] 30s refresh updates anomaly count
- [ ] Whitelist action suppresses future alerts
- [ ] Block action creates firewall rule (check with `netsh advfirewall firewall show rule name=all`)
- [ ] Kill action terminates process
- [ ] Toast notification appears for critical threats
- [ ] Non-admin mode runs without crash (process names may show "unknown")
- [ ] WSL2 ports tagged `[WSL2]` if WSL2 installed
- [ ] Extract-and-run from any directory works
