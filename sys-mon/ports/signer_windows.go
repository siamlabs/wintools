package ports

import (
	"fmt"
	"os"
	"strings"
)

// CheckSignature verifies if a binary file is signed and returns the publisher name.
func CheckSignature(path string) (bool, string) {
	if path == "" || path == "(NULL)" {
		return false, ""
	}

	// Check if file exists
	_, err := os.Stat(path)
	if err != nil {
		return false, ""
	}

	// signtool verify would require CGo or an external call.
	// For now, we mark based on Windows trust store lookup.
	// This is a placeholder — real implementation would call:
	//   signtool verify /pa <path>
	// or use CryptQueryObject via syscall.

	// Simple heuristic: check if the file exists and is not a system temp file
	if strings.Contains(path, "Temp") || strings.Contains(path, "tmp") {
		return false, ""
	}

	// For a real implementation, you'd call:
	//   exec.Command("signtool", "verify", "/pa", path)
	// and parse the output for the signer name.
	return false, ""
}
