package config

import (
	"fmt"
	"os"
	"time"

	"github.com/zeroroot-ai/gibson/internal/component"
)

// SandboxConfig configures the Gibson daemon's sandboxed-tool execution
// backend, which dispatches tool calls into Setec microVM sandboxes via
// gRPC instead of the default local/Redis-queue paths.
//
// When Enabled is false, the daemon does not construct a sandboxed executor
// and all tool calls take the existing paths unchanged. When Enabled is true
// but the Setec frontend is unreachable at startup, the daemon logs a warning
// and continues; individual sandboxed tool calls will fail at invocation time
// rather than at startup — per the design's Requirement 5.4.
type SandboxConfig struct {
	Enabled bool               `mapstructure:"enabled" yaml:"enabled"`
	Setec   SandboxSetecConfig `mapstructure:"setec" yaml:"setec"`
}

// SandboxSetecConfig describes how to reach and authenticate to the Setec
// frontend that this daemon dispatches sandboxed tool calls into.
type SandboxSetecConfig struct {
	Address     string              `mapstructure:"address" yaml:"address"`
	Tenant      string              `mapstructure:"tenant" yaml:"tenant"`
	CallTimeout time.Duration       `mapstructure:"call_timeout" yaml:"call_timeout"`
	MTLS        component.TLSConfig `mapstructure:"mtls" yaml:"mtls"`
}

// SandboxToolConfig / SandboxToolResources were removed under the
// gibson-tool-runner spec (task 16). Per-tool dispatch metadata now lives
// exclusively in ComponentRegistry entries written by the catalog
// refresher (see internal/daemon/catalog_refresher.go). If a future
// feature needs static per-tool config again, revive these types — but
// the preferred path is to extend the runner's --list-tools output so
// the catalog stays the single source of truth.

// Validate checks that a SandboxConfig with Enabled=true has every required
// field populated and references existing cert/key/ca files. Disabled configs
// skip all validation — the zero value is a valid disabled configuration.
func (c *SandboxConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Setec.Address == "" {
		return fmt.Errorf("sandbox.setec.address is required when sandbox.enabled=true")
	}
	if c.Setec.Tenant == "" {
		return fmt.Errorf("sandbox.setec.tenant is required when sandbox.enabled=true")
	}
	if c.Setec.CallTimeout <= 0 {
		c.Setec.CallTimeout = 5 * time.Minute
	}
	if !c.Setec.MTLS.Enabled {
		return fmt.Errorf("sandbox.setec.mtls.enabled must be true (Setec requires mTLS)")
	}
	for _, f := range []struct{ name, path string }{
		{"cert_file", c.Setec.MTLS.CertFile},
		{"key_file", c.Setec.MTLS.KeyFile},
		{"ca_file", c.Setec.MTLS.CAFile},
	} {
		if f.path == "" {
			return fmt.Errorf("sandbox.setec.mtls.%s is required when sandbox.enabled=true", f.name)
		}
		if _, err := os.Stat(f.path); err != nil {
			return fmt.Errorf("sandbox.setec.mtls.%s (%s): %w", f.name, f.path, err)
		}
	}
	return nil
}
