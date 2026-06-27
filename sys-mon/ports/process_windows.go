package ports

import (
	"fmt"
	"os/exec"
	"strings"
)

// ResolveProcess fills in Process, Path, ParentPID, and CommandLine for a PortInfo.
// Returns the port info with resolved fields.
func ResolveProcess(p PortInfo) PortInfo {
	if p.PID == 0 {
		return p
	}

	// Try tasklist to get process name
	name := resolveProcessName(p.PID)
	p.Process = name

	// Try to get path
	p.Path = resolveProcessPath(p.PID)

	// Try to get parent PID
	p.ParentPID = resolveParentPID(p.PID)

	// Try to get command line
	p.CommandLine = resolveCommandLine(p.PID)

	// Check WSL2
	p.WSL2 = isWSL2Process(p.PID, name, p.Family, p.Address)

	return p
}

func resolveProcessName(pid int) string {
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	// CSV format: "tasklist.exe","1234","Console","1","10,234 KB"
	fields := strings.Split(strings.TrimSpace(string(output)), ",")
	if len(fields) >= 1 {
		name := strings.Trim(fields[0], "\"")
		if name != "" {
			return name
		}
	}
	return "unknown"
}

func resolveProcessPath(pid int) string {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "ExecutablePath", "/value")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "ExecutablePath=") {
			path := strings.TrimPrefix(line, "ExecutablePath=")
			path = strings.TrimSpace(path)
			if path != "" && path != "(NULL)" {
				return path
			}
		}
	}
	return ""
}

func resolveParentPID(pid int) int {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "ParentProcessId", "/value")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "ParentProcessId=") {
			val := strings.TrimPrefix(line, "ParentProcessId=")
			val = strings.TrimSpace(val)
			if val != "" {
				ppid, err := fmt.Sscanf(val, "%d", new(int))
				_ = ppid
				if err == nil {
					var ppidInt int
					fmt.Sscanf(val, "%d", &ppidInt)
					return ppidInt
				}
			}
		}
	}
	return 0
}

func resolveCommandLine(pid int) string {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "CommandLine", "/value")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "CommandLine=") {
			cmdLine := strings.TrimPrefix(line, "CommandLine=")
			cmdLine = strings.TrimSpace(cmdLine)
			if cmdLine != "" && cmdLine != "(NULL)" {
				return cmdLine
			}
		}
	}
	return ""
}

// isWSL2Process checks if a PID belongs to a WSL2 process.
func isWSL2Process(pid int, processName string, family string, address string) bool {
	// WSL2 processes typically show as "vmmem" or "vmmemWSL"
	if strings.EqualFold(processName, "vmmem") || strings.EqualFold(processName, "vmmemWSL") {
		return true
	}

	// Check parent PID chain for WSL2
	ppid := resolveParentPID(pid)
	if ppid != 0 {
		ppName := resolveProcessName(ppid)
		if strings.EqualFold(ppName, "vmmem") || strings.EqualFold(ppName, "vmmemWSL") {
			return true
		}
	}

	// WSL2 IPv6 addresses are in the fdcf::/112 range
	if family == "ipv6" && strings.HasPrefix(address, "fdcf") {
		return true
	}

	return false
}
