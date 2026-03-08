package registry

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// AuthConfig holds authentication configuration for gRPC connections
type AuthConfig struct {
	// Token is a bearer token for authentication
	Token string

	// TokenFile is a path to a file containing the token
	// Useful for Kubernetes service account tokens
	TokenFile string

	// TokenRefreshInterval is how often to reload token from file
	// Only applies when TokenFile is set
	TokenRefreshInterval time.Duration
}

// GetToken returns the current authentication token
//
// If Token is set, it is returned directly.
// If TokenFile is set, the token is read from the file.
// If neither is set, returns an empty string (no authentication).
//
// This method is safe to call concurrently if Token is set.
// When using TokenFile, the caller should handle token refreshing
// by periodically calling this method.
func (c *AuthConfig) GetToken() (string, error) {
	if c.Token != "" {
		return c.Token, nil
	}
	if c.TokenFile != "" {
		data, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return "", fmt.Errorf("failed to read token file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", nil
}
