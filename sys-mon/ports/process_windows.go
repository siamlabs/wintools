package ports

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// ResolveProcess fills in Process, Path, ParentPID, and CommandLine for a PortInfo.
func ResolveProcess(p PortInfo) PortInfo {
	if p.PID == 0 {
		return p
	}

	name := resolveProcessName(p.PID)
	p.Process = name
	p.Path = resolveProcessPath(p.PID)
	p.ParentPID = resolveParentPID(p.PID)
	p.CommandLine = resolveCommandLine(p.PID)
	p.WSL2 = isWSL2Process(p.PID)
	p.Signed, p.Publisher = CheckSignature(p.Path)

	return p
}

func resolveProcessName(pid int) string {
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "JSON", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}

	var result struct {
		Info []struct {
			ImageName string `json:"Image Name"`
		} `json:"Info"`
	}
	if err := json.Unmarshal(output, &result); err == nil && len(result.Info) > 0 {
		return result.Info[0].ImageName
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
				var ppidInt int
				_, err := fmt.Sscanf(val, "%d", &ppidInt)
				if err == nil {
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
func isWSL2Process(pid int) bool {
	name := resolveProcessName(pid)
	if strings.EqualFold(name, "vmmem") || strings.EqualFold(name, "vmmemWSL") {
		return true
	}

	ppid := resolveParentPID(pid)
	if ppid != 0 {
		ppName := resolveProcessName(ppid)
		if strings.EqualFold(ppName, "vmmem") || strings.EqualFold(ppName, "vmmemWSL") {
			return true
		}
	}

	return false
}

// KillProcess terminates a process by PID.
func KillProcess(pid int) error {
	handle, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer syscall.CloseHandle(handle)

	err = syscall.TerminateProcess(handle, 1)
	if err != nil {
		return fmt.Errorf("terminate process %d: %w", pid, err)
	}
	return nil
}

// GetProcessDetails returns all process info for a given PID.
func GetProcessDetails(pid int) map[string]interface{} {
	p := PortInfo{PID: pid}
	p = ResolveProcess(p)
	return map[string]interface{}{
		"pid":          pid,
		"process":      p.Process,
		"path":         p.Path,
		"command_line": p.CommandLine,
		"parent_pid":   p.ParentPID,
		"wsl2":         p.WSL2,
		"signed":       p.Signed,
		"publisher":    p.Publisher,
	}
}
