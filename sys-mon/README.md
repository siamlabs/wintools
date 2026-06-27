# sys-mon

Lightweight port monitoring for Windows 11 — like **Procmon for network ports**.

Download, run, and get instant visibility into what's listening on your machine.

## Features

- **Real-time port scanning** — TCP/IPv4, TCP/IPv6, UDP/IPv4, UDP/IPv6
- **Baseline comparison** — save a "known good" snapshot and detect changes
- **Threat classification** — Critical / High / Medium / Low / Info / Gone
- **Process resolution** — PID, process name, executable path, signature verification
- **WSL2 detection** — auto-tags WSL2 ports to prevent false positives
- **Named baselines** — `sys-mon baseline save work`, `sys-mon baseline save home`
- **Whitelist** — mark ports as expected to suppress future alerts
- **System tray icon** — dynamic color (green/red/yellow/gray) with anomaly count
- **Windows toast notifications** — alerts for critical threats
- **Firewall block** — one-click `netsh` deny rule creation
- **Dual binary** — CLI (`sys-mon.exe`) + GUI panel (`sys-mon-panel.exe`)
- **Zero dependencies** — pure Go, single binary, no runtime installs
- **Low overhead** — <100ms startup, <2% CPU, minimal RAM

## Download

> **v0.1.0** — Initial release

| File | Size |
|------|------|
| `sys-mon-0.1.0-win64.zip` | ~12 MB |

Extract and run:
- `sys-mon.exe` — CLI (port scanning, baselines, threat analysis)
- `sys-mon-panel.exe` — GUI (tray icon, real-time monitoring, toast alerts)

## Quick Start

### CLI

```bash
# Scan and compare against baseline
sys-mon ports check default

# Save a baseline
sys-mon baseline save work

# List baselines
sys-mon baseline list

# Delete a baseline
sys-mon baseline delete work
```

### Panel

Run `sys-mon-panel.exe` to start the tray-based monitor:

1. Tray icon appears (green = clean, red = anomalies)
2. Right-click tray icon for menu (Open Panel, Start/Stop, Scan Now, Settings)
3. Click "Open Panel" for the full dashboard
4. Click "Whitelist" or "Block" on any anomaly

## Architecture

```
sys-mon/
├── cmd/
│   └── main.go          # CLI entry point
├── ports/
│   ├── types.go          # Data types (PortInfo, Baseline, Anomaly)
│   ├── collector_windows.go  # netstat -ano parsing + deduplication
│   ├── process_windows.go    # Process resolution (tasklist, wmic)
│   ├── signer_windows.go     # signtool signature verification
│   ├── baseline.go         # Save/load/list/delete baselines
│   ├── alert.go            # Text output formatter
│   └── baseline_test.go    # Unit tests (25 tests)
├── main.go               # Wails panel entry point
├── frontend/
│   ├── index.html        # Dark-themed UI
│   └── src/main.js       # Vanilla JS frontend
├── config/
│   └── baselines/        # Saved baseline JSON files
├── wails.json            # Wails build config
├── go.mod
└── README.md
```

## Threat Classification

| Level | Condition |
|-------|-----------|
| 🔴 Critical | Unknown process + High port + All interfaces + Unsigned |
| 🟠 High | Unknown process + Unsigned binary |
| 🟡 Medium | Known but not whitelisted OR Unsigned known process |
| 🟢 Low | Whitelisted / matches baseline |
| ⚪ Gone | Was in baseline, now missing |
| 🔵 Info | WSL2 / System / Firewall ports |

**UDP handling**: UDP anomalies default one threat level lower than TCP (lower C2 risk).

## Baseline JSON Schema

```json
{
  "version": 1,
  "name": "default",
  "captured_at": "2026-06-27T00:00:00Z",
  "hostname": "DESKTOP-12345",
  "admin": true,
  "ports": [
    {
      "address": "0.0.0.0",
      "port": 443,
      "protocol": "tcp",
      "family": "ipv4",
      "pid": 1234,
      "process": "nginx",
      "whitelisted": false,
      "signed": true,
      "publisher": "Let's Encrypt",
      "wsl2": false
    }
  ]
}
```

## Building from Source

```bash
# Install Wails CLI
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# Build CLI
go build -o sys-mon.exe ./cmd/

# Build Panel
wails build
```

## Testing

```bash
go test ./ports/ -v
```

25 tests covering: port keying, threat classification, baseline save/load/delete,
version migration, deduplication, signature checking, and process resolution.

## Technical Details

- **Port enumeration**: `netstat -ano` parsing with key-based deduplication
  (`proto/family/address:port`)
- **Process resolution**: `tasklist /FO JSON` + `wmic process where pid=X get`
- **Signature verification**: `signtool verify /pa` for real publisher names
- **WSL2 detection**: PID matching against WSL2 VM processes
- **Tray icon**: Win32 `Shell_NotifyIconW` API
- **Toast notifications**: PowerShell COM API (`Windows.UI.Notifications`)
- **Firewall block**: `netsh advfirewall firewall add rule`
- **Distribution**: Single `.zip` extract-and-run, no installer

## License

MIT
