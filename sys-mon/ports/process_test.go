package ports

import (
	"testing"
)

func TestKillProcessInvalidPID(t *testing.T) {
	// PID 0 should fail — no such process
	err := KillProcess(0)
	if err == nil {
		t.Error("KillProcess(0) should return error")
	}
}

func TestKillProcessNonExistent(t *testing.T) {
	// Very high PID almost certainly doesn't exist
	err := KillProcess(999999999)
	if err == nil {
		t.Error("KillProcess(999999999) should return error")
	}
}

func TestGetProcessDetailsValidPID(t *testing.T) {
	// PID 4 (System) should always exist
	details := GetProcessDetails(4)
	if details["process"] == "unknown" {
		t.Logf("PID 4 process = %q (may be non-admin)", details["process"])
	} else {
		t.Logf("PID 4 process = %q (admin)", details["process"])
	}
	if details["pid"] != 4 {
		t.Errorf("pid = %v, want 4", details["pid"])
	}
}

func TestGetProcessDetailsInvalidPID(t *testing.T) {
	details := GetProcessDetails(999999999)
	if details["process"] != "unknown" {
		t.Errorf("non-existent PID process = %q, want 'unknown'", details["process"])
	}
}

func TestResolveProcessNameZeroPID(t *testing.T) {
	p := PortInfo{PID: 0}
	p = ResolveProcess(p)
	if p.Process != "" {
		t.Errorf("PID 0 process = %q, want empty", p.Process)
	}
}
