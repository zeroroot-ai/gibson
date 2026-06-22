package daemon

import (
	"context"
	"fmt"
)

// startToolCatalogRefresher builds the CatalogRefresher from daemon config
// and starts its goroutine. Returns a non-fatal error on misconfiguration
// or Setec unavailability; the caller logs and continues so daemon
// startup never fails solely because the tool catalog is momentarily
// unreachable.
func (d *daemonImpl) startToolCatalogRefresher(ctx context.Context) error {
	if !d.config.ToolRunner.Enabled {
		return nil
	}
	if len(d.config.ToolRunner.Images) == 0 {
		return fmt.Errorf("tool_runner.enabled=true but no tool_runner.images configured")
	}
	if d.stateClient == nil {
		return fmt.Errorf("tool catalog refresher requires Redis state client")
	}
	if d.compRegistry == nil {
		return fmt.Errorf("tool catalog refresher requires ComponentRegistry")
	}

	// Build a dedicated Setec SandboxClient. The separate client keeps the
	// refresher's launches off the same gRPC stream the sandboxed executor
	// uses for tool calls.
	sbxClient, err := NewSetecSandboxClient(d.config.Sandbox)
	if err != nil {
		return fmt.Errorf("build setec sandbox client for refresher: %w", err)
	}
	if sbxClient == nil {
		return fmt.Errorf("setec_integration build tag not set; sandboxed catalog refresh is unavailable")
	}

	refresher, err := NewCatalogRefresher(CatalogRefresherConfig{
		Images:          d.config.ToolRunner.Images,
		RefreshInterval: d.config.ToolRunner.RefreshInterval,
		SandboxClient:   sbxClient,
		Tenant:          d.config.Sandbox.Setec.Tenant,
		Registry:        d.compRegistry,
		Redis:           d.stateClient.Client(),
		Logger:          d.logger.WithComponent("tool-catalog").Slog(),
	})
	if err != nil {
		return fmt.Errorf("construct catalog refresher: %w", err)
	}
	if err := refresher.Start(ctx); err != nil {
		return fmt.Errorf("start catalog refresher: %w", err)
	}
	d.toolCatalogRefresher = refresher
	d.logger.Info(ctx, "tool catalog refresher started",
		"images", d.config.ToolRunner.Images,
		"refresh_interval", d.config.ToolRunner.RefreshInterval,
	)
	return nil
}
