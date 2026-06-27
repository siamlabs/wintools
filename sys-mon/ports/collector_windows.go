package ports

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// GetPorts scans all TCP/UDP ports on IPv4 and IPv6 using netstat.
// Returns deduplicated port list — only one entry per unique (address, port, protocol, family).
func GetPorts() ([]PortInfo, error) {
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	// Dedup key: "proto/family/address:port"
	seen := make(map[string]bool)
	var ports []PortInfo
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "TCP") && !strings.HasPrefix(line, "UDP") {
			continue
		}
		p, err := parseNetstatLine(line)
		if err != nil {
			continue
		}

		// Skip entries with PID 0 (system/listening sockets with no process)
		if p.PID == 0 {
			continue
		}

		key := fmt.Sprintf("%s/%s/%s:%d", p.Protocol, p.Family, p.Address, p.Port)
		if seen[key] {
			continue
		}
		seen[key] = true

		ports = append(ports, p)
	}
	return ports, nil
}

func parseNetstatLine(line string) (PortInfo, error) {
	var p PortInfo
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return p, fmt.Errorf("too few fields")
	}

	proto := strings.ToLower(fields[0])
	switch {
	case strings.HasPrefix(proto, "tcp"):
		p.Protocol = "tcp"
	case strings.HasPrefix(proto, "udp"):
		p.Protocol = "udp"
	default:
		return p, fmt.Errorf("unknown protocol: %s", proto)
	}

	if strings.Contains(proto, "6") {
		p.Family = "ipv6"
	} else {
		p.Family = "ipv4"
	}

	localAddr := fields[1]
	host, portStr, err := net.SplitHostPort(localAddr)
	if err != nil {
		return p, fmt.Errorf("invalid address %q: %w", localAddr, err)
	}
	p.Address = host

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return p, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	p.Port = port

	pidStr := fields[len(fields)-1]
	pid, err := strconv.Atoi(pidStr)
	if err == nil {
		p.PID = pid
	}

	return p, nil
}
