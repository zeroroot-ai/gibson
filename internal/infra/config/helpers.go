package config

import (
	"os"
	"path/filepath"
)

// DefaultHomeDir returns the default Gibson home directory.
// It uses ~/.gibson or falls back to a temporary directory if user home cannot be determined.
func DefaultHomeDir() string {
	userHome, err := os.UserHomeDir()
	if err != nil {
		// Fallback to temporary directory if user home cannot be determined
		return filepath.Join(os.TempDir(), ".gibson")
	}
	return filepath.Join(userHome, ".gibson")
}

// DefaultConfigPath returns the default config file path for a given home directory
func DefaultConfigPath(homeDir string) string {
	return filepath.Join(homeDir, "config.yaml")
}
