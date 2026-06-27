# sys-mon

> Lightweight port monitoring for Windows 11 — detect unexpected port activity.

[![Windows 11](https://img.shields.io/badge/Windows-11-0078D6?style=flat&logo=windows)](https://www.microsoft.com/windows/windows-11)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

sys-mon monitors TCP and UDP ports across IPv4 and IPv6 on Windows 11, compares them against a user-defined baseline, and alerts on anomalies. It focuses on **ports that are not normally active** — the ones that matter.

## Why

Malware hides in plain sight by opening ports that look normal. `netstat` shows everything but tells you nothing about what's *unexpected*. sys-mon solves that by learning what's normal on your machine and flagging what isn't.

## Features

- **Port scanning** — TCP + UDP, IPv4 + IPv6
- **Baseline comparison** — first run captures your "normal," subsequent runs show only anomalies
- **Threat levels** — Critical → Info, computed dynamically from process, signature, and binding
- **Named baselines** — separate baselines for work, home, after updates
- **Floating alerts** — Windows toast notifications for Critical/High threats
- **Task tray icon** — always-visible status with dynamic color
- **Control panel** — small GUI with anomaly list, active ports, scheduling
- **CLI** — `sys-mon ports check`, `sys-mon baseline save`, etc.
- **Portable** — no installer, no registry, no runtime dependencies

## Quick Start

1. **Download** the latest release
2. **Extract** to any folder
3. **Run as Administrator**:
   ```
   Right-click sys-mon-panel.exe → Run as administrator
   ```
   Or from CLI:
   ```
   sys-mon ports baseline
   sys-mon ports check
   ```

> **Admin required** for full process name resolution. Without admin, sys-mon still works but shows PID only for unknown processes.

## Screenshots

### Control Panel

```
┌─────────────────────────────────────────────────┐
│  SYS-MON  [Baseline ▼]  ● 3 anomalies           │
├─────────────────────────────────────────────────┤
│  🔴 Critical: 1   🟠 High: 0   🟡 Medium: 2    │
│  🟢 Low: 0   ⚪ Gone: 0   🔵 Info: 5            │
├─────────────────────────────────────────────────┤
│  ANOMALIES                   ACTIVE PORTS       │
│  ┌──────────────────────┐  ┌────────────────┐  │
│  │ ⚠ 0.0.0.0:4444/tcp  │  │ ✓ :443/tcp    │  │
│  │    python3 (PID 1234)│  │    nginx       │  │
│  │    HIGH  ✕ unsigned  │  │    LOW  ✓ signed│  │
│  │    [✓] [✕]           │  │    [i]         │  │
│  ├──────────────────────┤  ├────────────────┤  │
│  │ ⚠ [::]:8443/tcp     │  │ ✓ :80/tcp     │  │
│  │    unknown (PID 9999)│  │    node        │  │
│  │    MEDIUM  ✕ unsigned│  │    LOW  ✓ signed│  │
│  │    [✓] [✕]           │  │    [i]         │  │
│  └──────────────────────┘  └────────────────┘  │
├─────────────────────────────────────────────────┤
│  ● Running  Last: 12:34  Every: [30]s [Stop] [Refresh]│
└─────────────────────────────────────────────────┘
```

### Task Tray

| State | Icon | Tooltip |
|-------|------|---------|
| Normal | 🟢 | `sys-mon — 0 anomalies` |
| Warnings | 🟡 | `sys-mon — 2 anomalies` |
| Critical | 🔴 | `sys-mon — 1 critical!` |
| Paused | ⚪ | `sys-mon — paused` |

## CLI Reference

```bash
# Baseline management
sys-mon baseline save [name]        # save current state (default: "default")
sys-mon baseline load [name]        # load a baseline (default: "default")
sys-mon baseline list               # show available baselines
sys-mon baseline delete [name]      # remove a baseline

# Port operations
sys-mon ports check [name]          # compare against baseline, show anomalies
sys-mon ports whitelist <port> [--protocol tcp|udp] [--family ipv4|ipv6]
sys-mon ports list                  # full port inventory
sys-mon ports watch --interval 30s  # continuous watch mode
```

## Threat Levels

| Level | Criteria | Action |
|-------|----------|--------|
| 🔴 Critical | Unknown process + high port + bound to all interfaces + unsigned | Block + investigate |
| 🟠 High | Unknown process + any bind address + unsigned | Investigate |
| 🟡 Medium | Known process but not whitelisted, or unsigned known process | Whitelist or investigate |
| 🟢 Low | Whitelisted / baseline | No action |
| ⚪ Gone | Was in baseline, now missing | Confirm expected shutdown |
| 🔵 Info | WSL2 port / system port / firewall port | Informational |

## Resource Profile

| Metric | Value |
|--------|-------|
| Idle memory (CLI) | ~5 MB |
| Idle memory (panel) | ~15-20 MB |
| CPU (idle) | ~0% |
| CPU (per scan) | <1% for ~10ms |
| Disk (total) | ~5-20 MB |
| Startup | <100ms |

## How It Works

1. **Scan** — queries `netstat -ano` for all listening ports
2. **Resolve** — maps PID → process name, path, parent PID, command line
3. **Detect** — checks for WSL2 processes, auto-tags them
4. **Compare** — diffs against the loaded baseline
5. **Classify** — assigns threat level based on process, signature, binding, and protocol
6. **Alert** — shows in panel, sends toast for Critical/High, updates tray icon

## Building from Source

### Prerequisites

- [Go 1.21+](https://go.dev/dl/) — the only dependency
- [Wails CLI](https://wails.io/docs/gettingstarted/installation/) — `go install github.com/wailsapp/wails/v2/cmd/wails@latest`

### Build CLI only

```bash
cd wintools/sys-mon
go build -o sys-mon.exe .
```

### Build panel (GUI)

```bash
cd wintools/sys-mon
wails build
# Output: target/bundle/windows/sys-mon-panel.exe
```

### Quick Test (CLI only)

```bash
# Capture your current ports as baseline
sys-mon baseline save

# Then check
sys-mon ports check
```

## Architecture

```
wintools/sys-mon/
├── main.go              # Wails app entry point + tray icon
├── cmd/
│   └── main.go          # CLI entry point (separate binary)
├── ports/
│   ├── types.go          # PortInfo, Baseline, Anomaly types
│   ├── collector_windows.go # netstat-based port scanning
│   ├── process_windows.go  # PID → process name, path, parent, cmdline
│   ├── baseline.go       # baseline capture/save/load/compare/migrate
│   ├── threat.go         # threat level classification
│   ├── wsl2.go           # WSL2 detection
│   ├── signer.go         # binary signature verification
│   └── alert.go          # text output formatting
├── frontend/             # Wails webview UI (HTML/CSS/JS)
│   ├── index.html        # Dark-themed UI
│   └── src/
│       └── main.js       # DOM-based UI, Wails IPC calls
├── wails.json            # Wails build config
├── config/
│   └── baselines/        # named baseline storage
├── tests/
└── README.md
```

## Comparison

| Tool | What it does | What sys-mon adds |
|------|-------------|-------------------|
| `netstat` | Lists all ports | Baseline diff, threat levels |
| `tcpview` | GUI port viewer | Anomaly detection, alerts |
| Procmon | Kernel-level tracing | No driver, lightweight, port-focused |
| Windows Firewall | Manages rules | Detects before you need to block |

## License

MIT — use it, modify it, share it.

## Contributing

Issues and PRs welcome. For new features, open an issue first to discuss.

## Acknowledgments

- [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/) — inspiration for portable Windows tools
- [Wails](https://wails.io/) — for the lightweight Go + webview framework
- [netstat](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) — Windows built-in port enumeration
