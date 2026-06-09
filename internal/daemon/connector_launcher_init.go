package daemon

// connector_launcher_init.go constructs the hosted MCP-connector launcher
// (gibson#684, ADR-0048 Option 1) from the daemon's sandbox configuration.
// Tag-free: it relies on NewSetecSandboxClient, which has a no-op variant in
// builds without setec_integration, so this file needs no build-tag split.

import (
	"context"
	"log/slog"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/admin"
	"github.com/zeroroot-ai/gibson/internal/config"
	"github.com/zeroroot-ai/gibson/internal/connector"
	"github.com/zeroroot-ai/gibson/internal/harness/sandboxed"
)

// NewConnectorLauncher builds the admin.ConnectorLauncher for hosted MCP
// connector registrations. Returns (nil, nil) — launch unavailable, connector
// registrations rejected with a clear error while plain plugins keep working —
// when sandboxing is disabled, the binary lacks setec_integration, or
// sandbox.connector.runner_image is unset. Returns (nil, err) on genuine
// misconfiguration (e.g. setec mTLS failure) so the caller can log it.
func NewConnectorLauncher(cfg config.SandboxConfig, logger *slog.Logger, admit func(context.Context, auth.TenantID) error) (admin.ConnectorLauncher, error) {
	if !cfg.Enabled || cfg.Connector.RunnerImage == "" {
		return nil, nil
	}

	client, err := NewSetecSandboxClient(cfg)
	if err != nil {
		return nil, err
	}
	if client == nil {
		// Built without setec_integration.
		return nil, nil
	}

	egress := make([]sandboxed.EgressRule, 0, len(cfg.Connector.PlatformEgress))
	for _, e := range cfg.Connector.PlatformEgress {
		egress = append(egress, sandboxed.EgressRule{Host: e.Host, Port: e.Port})
	}

	l, err := connector.New(connector.Config{
		Client:         client,
		RunnerImage:    cfg.Connector.RunnerImage,
		PlatformURL:    cfg.Connector.PlatformURL,
		PlatformEgress: egress,
		VCPU:           cfg.Connector.VCPU,
		Memory:         cfg.Connector.Memory,
		Admit:          admit,
		Logger:         logger,
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}
