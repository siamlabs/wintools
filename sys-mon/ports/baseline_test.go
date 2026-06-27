package ports

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPortKey(t *testing.T) {
	p := PortInfo{Address: "0.0.0.0", Port: 443, Protocol: "tcp", Family: "ipv4"}
	key := portKey(p)
	expected := "0.0.0.0:443:tcp:ipv4"
	if key != expected {
		t.Errorf("portKey() = %q, want %q", key, expected)
	}
}

func TestPortKeyIPv6(t *testing.T) {
	p := PortInfo{Address: "::", Port: 80, Protocol: "tcp", Family: "ipv6"}
	key := portKey(p)
	expected := ":::80:tcp:ipv6"
	if key != expected {
		t.Errorf("portKey() = %q, want %q", key, expected)
	}
}

func TestClassifyThreatNewUnsigned(t *testing.T) {
	p := PortInfo{PID: 9999, Process: "unknown", Signed: false, Protocol: "tcp", WSL2: false}
	threat := classifyThreat(p, PortInfo{}, true)
	if threat != "high" {
		t.Errorf("classifyThreat(unknown, unsigned, tcp, new) = %q, want %q", threat, "high")
	}
}

func TestClassifyThreatNewSigned(t *testing.T) {
	p := PortInfo{PID: 9999, Process: "chrome.exe", Signed: true, Protocol: "tcp", WSL2: false}
	threat := classifyThreat(p, PortInfo{}, true)
	if threat != "medium" {
		t.Errorf("classifyThreat(chrome, signed, tcp, new) = %q, want %q", threat, "medium")
	}
}

func TestClassifyThreatWSL2(t *testing.T) {
	p := PortInfo{PID: 1234, Process: "vmmem", Signed: false, Protocol: "tcp", WSL2: true}
	threat := classifyThreat(p, PortInfo{}, true)
	if threat != "info" {
		t.Errorf("classifyThreat(vmmem, wsl2) = %q, want %q", threat, "info")
	}
}

func TestClassifyThreatUDPDowngrade(t *testing.T) {
	p := PortInfo{PID: 9999, Process: "unknown", Signed: false, Protocol: "udp", WSL2: false}
	threat := classifyThreat(p, PortInfo{}, true)
	if threat != "medium" {
		t.Errorf("classifyThreat(unknown, unsigned, udp, new) = %q, want %q (downgraded from high)", threat, "medium")
	}
}

func TestClassifyThreatWhitelisted(t *testing.T) {
	p := PortInfo{PID: 1234, Process: "nginx", Signed: true, Protocol: "tcp", WSL2: false, Whitelisted: true}
	threat := classifyThreat(p, PortInfo{}, false)
	if threat != "low" {
		t.Errorf("classifyThreat(nginx, whitelisted) = %q, want %q", threat, "low")
	}
}

func TestClassifyThreatSystem(t *testing.T) {
	p := PortInfo{PID: 4, Process: "System", Signed: false, Protocol: "tcp", WSL2: false}
	threat := classifyThreat(p, PortInfo{}, false)
	if threat != "info" {
		t.Errorf("classifyThreat(System) = %q, want %q", threat, "info")
	}
}

func TestGetRecommendedAction(t *testing.T) {
	tests := []struct {
		name     string
		p        PortInfo
		isNew    bool
		expected string
	}{
		{
			name:     "unknown new process",
			p:        PortInfo{PID: 9999, Process: "unknown"},
			isNew:    true,
			expected: "Investigate process",
		},
		{
			name:     "signed new process",
			p:        PortInfo{PID: 1234, Process: "chrome.exe", Signed: true},
			isNew:    true,
			expected: "Whitelist if expected",
		},
		{
			name:     "unsigned changed process",
			p:        PortInfo{PID: 1234, Process: "node.exe", Signed: false, Whitelisted: false},
			isNew:    false,
			expected: "Whitelist or investigate",
		},
		{
			name:     "whitelisted process",
			p:        PortInfo{PID: 1234, Process: "nginx", Signed: true, Whitelisted: true},
			isNew:    false,
			expected: "No action",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := getRecommendedAction(tt.p, PortInfo{}, tt.isNew)
			if action != tt.expected {
				t.Errorf("getRecommendedAction() = %q, want %q", action, tt.expected)
			}
		})
	}
}

func TestCompareBaselineNewPort(t *testing.T) {
	base := &Baseline{
		Version:    1,
		Name:       "test",
		CapturedAt: "2026-06-27T00:00:00Z",
		Hostname:   "test",
		Ports: []PortInfo{
			{Address: "0.0.0.0", Port: 80, Protocol: "tcp", Family: "ipv4", PID: 100, Process: "nginx"},
		},
	}

	current := []PortInfo{
		{Address: "0.0.0.0", Port: 80, Protocol: "tcp", Family: "ipv4", PID: 100, Process: "nginx"},
		{Address: "0.0.0.0", Port: 4444, Protocol: "tcp", Family: "ipv4", PID: 9999, Process: "unknown"},
	}

	anomalies := CompareBaseline(base, current)
	if len(anomalies) != 1 {
		t.Errorf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0].Type != AnomalyNew {
		t.Errorf("expected NEW anomaly, got %s", anomalies[0].Type)
	}
}

func TestCompareBaselineGonePort(t *testing.T) {
	base := &Baseline{
		Version:    1,
		Name:       "test",
		CapturedAt: "2026-06-27T00:00:00Z",
		Hostname:   "test",
		Ports: []PortInfo{
			{Address: "0.0.0.0", Port: 80, Protocol: "tcp", Family: "ipv4", PID: 100, Process: "nginx"},
			{Address: "0.0.0.0", Port: 443, Protocol: "tcp", Family: "ipv4", PID: 100, Process: "nginx"},
		},
	}

	current := []PortInfo{
		{Address: "0.0.0.0", Port: 80, Protocol: "tcp", Family: "ipv4", PID: 100, Process: "nginx"},
	}

	anomalies := CompareBaseline(base, current)
	if len(anomalies) != 1 {
		t.Errorf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0].Type != AnomalyGone {
		t.Errorf("expected GONE anomaly, got %s", anomalies[0].Type)
	}
}

func TestCompareBaselineNoChange(t *testing.T) {
	base := &Baseline{
		Version:    1,
		Name:       "test",
		CapturedAt: "2026-06-27T00:00:00Z",
		Hostname:   "test",
		Ports: []PortInfo{
			{Address: "0.0.0.0", Port: 80, Protocol: "tcp", Family: "ipv4", PID: 100, Process: "nginx"},
		},
	}

	current := []PortInfo{
		{Address: "0.0.0.0", Port: 80, Protocol: "tcp", Family: "ipv4", PID: 100, Process: "nginx"},
	}

	anomalies := CompareBaseline(base, current)
	if len(anomalies) != 0 {
		t.Errorf("expected 0 anomalies, got %d", len(anomalies))
	}
}

func TestCompareBaselineChangedPID(t *testing.T) {
	base := &Baseline{
		Version:    1,
		Name:       "test",
		CapturedAt: "2026-06-27T00:00:00Z",
		Hostname:   "test",
		Ports: []PortInfo{
			{Address: "0.0.0.0", Port: 80, Protocol: "tcp", Family: "ipv4", PID: 100, Process: "nginx"},
		},
	}

	current := []PortInfo{
		{Address: "0.0.0.0", Port: 80, Protocol: "tcp", Family: "ipv4", PID: 200, Process: "nginx"},
	}

	anomalies := CompareBaseline(base, current)
	if len(anomalies) != 1 {
		t.Errorf("expected 1 anomaly, got %d", len(anomalies))
	}
	if anomalies[0].Type != AnomalyChanged {
		t.Errorf("expected CHANGED anomaly, got %s", anomalies[0].Type)
	}
}

func TestFormatAnomaliesTextEmpty(t *testing.T) {
	text := FormatAnomaliesText([]Anomaly{})
	expected := "✓ No anomalies detected. All ports match baseline.\n"
	if text != expected {
		t.Errorf("FormatAnomaliesText([]) = %q, want %q", text, expected)
	}
}

func TestBaselineDirExists(t *testing.T) {
	dir := DefaultBaselineDir()
	if dir == "" {
		t.Error("DefaultBaselineDir() returned empty string")
	}
}

func TestBaselinePath(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{name: "default", expected: "default.json"},
		{name: "work", expected: "work.json"},
		{name: "home", expected: "home.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := BaselinePath(tt.name)
			base := filepath.Base(path)
			if base != tt.expected {
				t.Errorf("BaselinePath(%q) = %q, want base %q", tt.name, base, tt.expected)
			}
		})
	}
}

func TestCheckAdmin(t *testing.T) {
	// This test may fail in non-admin environments — just verify it returns a bool
	admin := checkAdmin()
	t.Logf("checkAdmin() = %v (expected: depends on execution context)", admin)
}

func TestCheckSignatureNonExistent(t *testing.T) {
	signed, publisher := CheckSignature("C:\\nonexistent\\file.exe")
	if signed {
		t.Error("CheckSignature(nonexistent) should return false")
	}
	if publisher != "" {
		t.Errorf("CheckSignature(nonexistent) publisher = %q, want empty", publisher)
	}
}

func TestCheckSignatureEmptyPath(t *testing.T) {
	signed, publisher := CheckSignature("")
	if signed {
		t.Error("CheckSignature(\"\") should return false")
	}
	if publisher != "" {
		t.Errorf("CheckSignature(\"\") publisher = %q, want empty", publisher)
	}
}

func TestCheckSignatureNullPath(t *testing.T) {
	signed, publisher := CheckSignature("(NULL)")
	if signed {
		t.Error("CheckSignature(\"(NULL)\") should return false")
	}
	if publisher != "" {
		t.Errorf("CheckSignature(\"(NULL)\") publisher = %q, want empty", publisher)
	}
}

func TestGetPortsReturnsPorts(t *testing.T) {
	ports, err := GetPorts()
	if err != nil {
		t.Fatalf("GetPorts() error: %v", err)
	}
	if len(ports) == 0 {
		t.Error("GetPorts() returned no ports")
	}
	t.Logf("GetPorts() returned %d ports", len(ports))
}

func TestGetPortsDeduplication(t *testing.T) {
	ports, err := GetPorts()
	if err != nil {
		t.Fatalf("GetPorts() error: %v", err)
	}

	// Check for duplicates
	seen := make(map[string]bool)
	for _, p := range ports {
		key := portKey(p)
		if seen[key] {
			t.Errorf("Duplicate port found: %s", key)
		}
		seen[key] = true
	}
}

func TestGetPortsNoPIDZero(t *testing.T) {
	ports, err := GetPorts()
	if err != nil {
		t.Fatalf("GetPorts() error: %v", err)
	}

	for _, p := range ports {
		if p.PID == 0 {
			t.Errorf("Port with PID 0 found: %s:%d/%s", p.Address, p.Port, p.Protocol)
		}
	}
}

func TestBaselineSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()

	ports := []PortInfo{
		{Address: "0.0.0.0", Port: 80, Protocol: "tcp", Family: "ipv4", PID: 100, Process: "nginx"},
	}

	// Save to temp dir
	testBaselineDir = tmpDir
	if err := SaveBaseline("test", ports); err != nil {
		t.Fatalf("SaveBaseline() error: %v", err)
	}

	// Load
	b, err := LoadBaseline("test")
	if err != nil {
		t.Fatalf("LoadBaseline() error: %v", err)
	}
	if b.Name != "test" {
		t.Errorf("baseline name = %q, want %q", b.Name, "test")
	}
	if len(b.Ports) != 1 {
		t.Errorf("baseline ports = %d, want 1", len(b.Ports))
	}

	// List
	names, err := ListBaselines()
	if err != nil {
		t.Fatalf("ListBaselines() error: %v", err)
	}
	if len(names) != 1 || names[0] != "test" {
		t.Errorf("ListBaselines() = %v, want [test]", names)
	}

	// Delete
	if err := DeleteBaseline("test"); err != nil {
		t.Fatalf("DeleteBaseline() error: %v", err)
	}

	// Verify deleted
	names, err = ListBaselines()
	if err != nil {
		t.Fatalf("ListBaselines() after delete error: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("ListBaselines() after delete = %v, want []", names)
	}
}

func TestBaselineVersionMigration(t *testing.T) {
	tmpDir := t.TempDir()
	testBaselineDir = tmpDir

	// Write a baseline with old version
	oldBaseline := `{
  "version": 0,
  "name": "old",
  "captured_at": "2026-01-01T00:00:00Z",
  "hostname": "test",
  "admin": false,
  "ports": [
    {"address": "0.0.0.0", "port": 80, "protocol": "tcp", "family": "ipv4", "pid": 100, "process": "nginx"}
  ]
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "old.json"), []byte(oldBaseline), 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	// Load — should migrate
	b, err := LoadBaseline("old")
	if err != nil {
		t.Fatalf("LoadBaseline() error: %v", err)
	}
	if b.Version != baselineSchemaVersion {
		t.Errorf("baseline version = %d, want %d (migrated)", b.Version, baselineSchemaVersion)
	}
}
