package ports

import (
	"os/exec"
	"strings"
)

// CheckSignature verifies if a binary file is signed and returns the publisher name.
func CheckSignature(path string) (bool, string) {
	if path == "" || path == "(NULL)" {
		return false, ""
	}

	// Check if file exists
	if _, err := exec.Command("cmd", "/c", "dir", path).Output(); err != nil {
		return false, ""
	}

	// Use signtool to verify signature
	cmd := exec.Command("signtool", "verify", "/pa", path)
	output, err := cmd.Output()
	if err != nil {
		return false, ""
	}

	// Parse publisher from output
	// signtool output: "Issuer: Microsoft Corporation" or "Signer: ..."
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "issuer:") {
			publisher := strings.TrimSpace(strings.TrimPrefix(line, "Issuer:"))
			if publisher != "" {
				return true, publisher
			}
		}
		if strings.HasPrefix(strings.ToLower(line), "signer:") {
			publisher := strings.TrimSpace(strings.TrimPrefix(line, "Signer:"))
			if publisher != "" {
				return true, publisher
			}
		}
	}

	// If signtool succeeded but we couldn't parse publisher, it's still signed
	if err == nil {
		return true, "Unknown Publisher"
	}

	return false, ""
}
