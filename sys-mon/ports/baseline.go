package ports

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const baselineSchemaVersion = 1

// testBaselineDir allows tests to override the baseline directory.
var testBaselineDir string

// DefaultBaselineDir returns the default baselines directory.
func DefaultBaselineDir() string {
	if testBaselineDir != "" {
		return testBaselineDir
	}
	// Store in the same directory as the executable
	exe, err := os.Executable()
	if err != nil {
		// Fallback to current directory
		return "config/baselines"
	}
	return filepath.Join(filepath.Dir(exe), "config", "baselines")
}

// BaselinePath returns the path to a named baseline file.
func BaselinePath(name string) string {
	dir := DefaultBaselineDir()
	return filepath.Join(dir, name+".json")
}

// SaveBaseline saves a baseline to disk.
func SaveBaseline(name string, ports []PortInfo) error {
	hostname, _ := os.Hostname()

	// Check if running as admin
	admin := checkAdmin()

	b := &Baseline{
		Version:    baselineSchemaVersion,
		Name:       name,
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
		Hostname:   hostname,
		Admin:      admin,
		Ports:      ports,
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}

	dir := DefaultBaselineDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create baseline dir: %w", err)
	}

	path := BaselinePath(name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}

	return nil
}

// LoadBaseline loads a baseline from disk.
func LoadBaseline(name string) (*Baseline, error) {
	path := BaselinePath(name)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %q: %w", name, err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %q: %w", name, err)
	}

	// Schema migration
	if b.Version < baselineSchemaVersion {
		migrateBaseline(&b)
	}

	return &b, nil
}

// ListBaselines returns the names of all available baselines.
func ListBaselines() ([]string, error) {
	dir := DefaultBaselineDir()

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read baselines dir: %w", err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	return names, nil
}

// DeleteBaseline removes a baseline from disk.
func DeleteBaseline(name string) error {
	path := BaselinePath(name)
	return os.Remove(path)
}

// CompareBaseline compares current ports against a baseline and returns anomalies.
func CompareBaseline(baseline *Baseline, current []PortInfo) []Anomaly {
	// Build lookup maps
	baselineMap := make(map[string]PortInfo)
	for _, p := range baseline.Ports {
		key := portKey(p)
		baselineMap[key] = p
	}

	currentMap := make(map[string]PortInfo)
	for _, p := range current {
		key := portKey(p)
		currentMap[key] = p
	}

	var anomalies []Anomaly

	// Check for new and changed ports
	for key, cur := range currentMap {
		if base, ok := baselineMap[key]; ok {
			// Port exists in baseline — check if it changed
			if base.PID != cur.PID || base.Process != cur.Process {
				anomalies = append(anomalies, Anomaly{
					Type:      AnomalyChanged,
					PortInfo:  cur,
					Threat:    classifyThreat(cur, base, false),
					RecommendedAction: getRecommendedAction(cur, base, false),
				})
			}
		} else {
			// New port
			anomalies = append(anomalies, Anomaly{
				Type:      AnomalyNew,
				PortInfo:  cur,
				Threat:    classifyThreat(cur, PortInfo{}, true),
				RecommendedAction: getRecommendedAction(cur, PortInfo{}, true),
			})
		}
	}

	// Check for gone ports
	for key, base := range baselineMap {
		if _, ok := currentMap[key]; !ok {
			anomalies = append(anomalies, Anomaly{
				Type:      AnomalyGone,
				PortInfo:  base,
				Threat:    "gone",
				RecommendedAction: "Confirm expected shutdown",
			})
		}
	}

	return anomalies
}

// portKey creates a unique key for a port entry.
func portKey(p PortInfo) string {
	return fmt.Sprintf("%s:%d:%s:%s", p.Address, p.Port, p.Protocol, p.Family)
}

// classifyThreat assigns a threat level to a port.
func classifyThreat(p PortInfo, baseline PortInfo, isNew bool) string {
	// WSL2 or system ports are informational
	if p.WSL2 {
		return "info"
	}
	if p.PID == 4 || strings.EqualFold(p.Process, "system") || strings.EqualFold(p.Process, "svchost.exe") {
		return "info"
	}

	// UDP gets one level lower than TCP
	udpDowngrade := p.Protocol == "udp"

	if isNew {
		if p.PID == 0 || strings.EqualFold(p.Process, "unknown") {
			if !p.Signed {
				if udpDowngrade {
					return "medium"
				}
				return "high"
			}
			if udpDowngrade {
				return "low"
			}
			return "medium"
		}
		if !p.Signed {
			if udpDowngrade {
				return "medium"
			}
			return "high"
		}
		return "medium"
	}

	// Changed port
	if !p.Whitelisted {
		if !p.Signed {
			if udpDowngrade {
				return "medium"
			}
			return "high"
		}
		return "medium"
	}

	return "low"
}

// getRecommendedAction returns the recommended action for a threat.
func getRecommendedAction(p PortInfo, baseline PortInfo, isNew bool) string {
	if isNew {
		if p.PID == 0 || strings.EqualFold(p.Process, "unknown") {
			return "Investigate process"
		}
		if !p.Signed {
			return "Whitelist or investigate"
		}
		return "Whitelist if expected"
	}

	if !p.Whitelisted {
		if !p.Signed {
			return "Whitelist or investigate"
		}
		return "Whitelist if expected"
	}

	return "No action"
}

// migrateBaseline upgrades an older baseline to the current schema.
func migrateBaseline(b *Baseline) {
	// Add missing fields, normalize data, etc.
	// Version 1 → 2 migrations go here.
	b.Version = baselineSchemaVersion
}

func checkAdmin() bool {
	cmd := exec.Command("whoami", "/groups", "-id", "S-1-16-12288") // Administrators SID
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(output)), "administrators")
}
