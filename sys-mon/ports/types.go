package ports

// PortInfo represents a single listening port entry.
type PortInfo struct {
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"` // "tcp" or "udp"
	Family    string `json:"family"`   // "ipv4" or "ipv6"
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	Whitelisted bool `json:"whitelisted"`
	Signed    bool   `json:"signed"`
	Publisher string `json:"publisher,omitempty"`
	WSL2      bool   `json:"wsl2"`
	Path      string `json:"path,omitempty"`
	ParentPID int    `json:"parent_pid,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
}

// Baseline represents a saved port snapshot.
type Baseline struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	CapturedAt string   `json:"captured_at"`
	Hostname  string    `json:"hostname"`
	Admin     bool      `json:"admin"`
	Ports     []PortInfo `json:"ports"`
}

// AnomalyType classifies what changed.
type AnomalyType string

const (
	AnomalyNew   AnomalyType = "NEW"
	AnomalyGone  AnomalyType = "GONE"
	AnomalyChanged AnomalyType = "CHANGED"
)

// Anomaly represents a port that differs from the baseline.
type Anomaly struct {
	Type      AnomalyType `json:"type"`
	PortInfo  PortInfo    `json:"port"`
	Threat    string      `json:"threat"`    // "critical", "high", "medium", "low", "gone", "info"
	RecommendedAction string `json:"recommended_action"`
}
