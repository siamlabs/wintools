package ports

import (
	"fmt"
	"strings"
)

// FormatAnomaliesText returns a human-readable text output of anomalies.
func FormatAnomaliesText(anomalies []Anomaly) string {
	var sb strings.Builder

	if len(anomalies) == 0 {
		sb.WriteString("✓ No anomalies detected. All ports match baseline.\n")
		return sb.String()
	}

	// Count by threat
	counts := make(map[string]int)
	for _, a := range anomalies {
		counts[a.Threat]++
	}

	sb.WriteString(fmt.Sprintf("Found %d anomaly/anomalies:\n", len(anomalies)))
	sb.WriteString(fmt.Sprintf("  🔴 Critical: %d  🟠 High: %d  🟡 Medium: %d  🟢 Low: %d  ⚪ Gone: %d  🔵 Info: %d\n\n",
		counts["critical"], counts["high"], counts["medium"], counts["low"], counts["gone"], counts["info"]))

	for _, a := range anomalies {
		sb.WriteString(formatAnomalyLine(a))
		sb.WriteString("\n")
	}

	return sb.String()
}

func formatAnomalyLine(a Anomaly) string {
	var sb strings.Builder

	switch a.Threat {
	case "critical":
		sb.WriteString(fmt.Sprintf("  🔴 CRITICAL: %s\n", formatPort(a.PortInfo)))
	case "high":
		sb.WriteString(fmt.Sprintf("  🟠 HIGH:     %s\n", formatPort(a.PortInfo)))
	case "medium":
		sb.WriteString(fmt.Sprintf("  🟡 MEDIUM:   %s\n", formatPort(a.PortInfo)))
	case "low":
		sb.WriteString(fmt.Sprintf("  🟢 LOW:      %s\n", formatPort(a.PortInfo)))
	case "gone":
		sb.WriteString(fmt.Sprintf("  ⚪ GONE:      %s\n", formatPort(a.PortInfo)))
	case "info":
		sb.WriteString(fmt.Sprintf("  🔵 INFO:      %s\n", formatPort(a.PortInfo)))
	default:
		sb.WriteString(fmt.Sprintf("  ? UNKNOWN:   %s\n", formatPort(a.PortInfo)))
	}

	sb.WriteString(fmt.Sprintf("     PID: %d  Process: %s\n", a.PortInfo.PID, a.PortInfo.Process))
	if a.PortInfo.WSL2 {
		sb.WriteString("     [WSL2]\n")
	}
	if a.PortInfo.Path != "" {
		sb.WriteString(fmt.Sprintf("     Path: %s\n", a.PortInfo.Path))
	}
	sb.WriteString(fmt.Sprintf("     Action: %s\n", a.RecommendedAction))

	return sb.String()
}

func formatPort(p PortInfo) string {
	addr := p.Address
	if p.Family == "ipv6" && addr != "::" && addr != "::1" {
		return fmt.Sprintf("[%s]:%d/%s", addr, p.Port, p.Protocol)
	}
	return fmt.Sprintf("%s:%d/%s", addr, p.Port, p.Protocol)
}
