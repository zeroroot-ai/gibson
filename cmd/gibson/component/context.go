package component

import (
	"context"
	"os"

	"github.com/zero-day-ai/gibson/internal/registry"
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

// RegistryManagerKey is the context key for storing the registry manager.
// This is ONLY used for daemon-internal operations (attack, orchestrator) that
// need registry access. CLI commands should use GetDaemonClient instead.
type RegistryManagerKey struct{}

// GetRegistryManager retrieves the registry manager from the context.
// This is ONLY for daemon-internal operations. Returns nil if not present.
func GetRegistryManager(ctx context.Context) *registry.Manager {
	if m, ok := ctx.Value(RegistryManagerKey{}).(*registry.Manager); ok {
		return m
	}
	return nil
}

// WithRegistryManager returns a new context with the registry manager attached.
// This is ONLY for daemon-internal operations.
func WithRegistryManager(ctx context.Context, m *registry.Manager) context.Context {
	return context.WithValue(ctx, RegistryManagerKey{}, m)
}
