package component

import (
	"context"
	"os"

	internalcomponent "github.com/zero-day-ai/gibson/internal/component"
)

// getGibsonHome returns the Gibson home directory.
func getGibsonHome() (string, error) {
	homeDir := os.Getenv("GIBSON_HOME")
	if homeDir == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		homeDir = userHome + "/.gibson"
	}
	return homeDir, nil
}

// daemonClientKey is the context key for storing the daemon client.
type daemonClientKey struct{}

// GetDaemonClient retrieves the daemon client from the context.
// Returns nil if the client is not present in the context.
func GetDaemonClient(ctx context.Context) interface{} {
	return ctx.Value(daemonClientKey{})
}

// WithDaemonClient returns a new context with the daemon client attached.
func WithDaemonClient(ctx context.Context, client interface{}) context.Context {
	return context.WithValue(ctx, daemonClientKey{}, client)
}

// componentDiscoveryKey is the context key for injecting a ComponentDiscovery mock in tests.
type componentDiscoveryKey struct{}

// GetComponentDiscovery retrieves an injected ComponentDiscovery from the context.
// This is used in tests to inject a mock discovery without a real Redis connection.
// Returns nil if not present (normal production path).
func GetComponentDiscovery(ctx context.Context) internalcomponent.ComponentDiscovery {
	if d, ok := ctx.Value(componentDiscoveryKey{}).(internalcomponent.ComponentDiscovery); ok {
		return d
	}
	return nil
}

// WithComponentDiscovery returns a new context with a ComponentDiscovery injected.
// Used in tests to inject a mock discovery implementation.
func WithComponentDiscovery(ctx context.Context, d internalcomponent.ComponentDiscovery) context.Context {
	return context.WithValue(ctx, componentDiscoveryKey{}, d)
}
