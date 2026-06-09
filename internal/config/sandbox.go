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
	Enabled   bool                   `mapstructure:"enabled" yaml:"enabled"`
	Setec     SandboxSetecConfig     `mapstructure:"setec" yaml:"setec"`
	Connector SandboxConnectorConfig `mapstructure:"connector" yaml:"connector"`
}

// SandboxConnectorConfig configures hosted MCP-connector launches
// (gibson#684, ADR-0048 Option 1): the generic MCP-bridge runner image and
// the platform endpoints every connector sandbox must reach. When
// RunnerImage is empty, hosted connector launch is unavailable and connector
// registrations are rejected with a clear error.
type SandboxConnectorConfig struct {
	// RunnerImage is the OCI reference of the generic MCP-bridge runner,
	// e.g. ghcr.io/zeroroot-ai/gibson-mcp-bridge-runner:v0.107.0.
	RunnerImage string `mapstructure:"runner_image" yaml:"runner_image"`

	// PlatformURL is the gibson base URL the bridge dials from inside the
	// sandbox (capability-grant register, ComponentService, GetCredential).
	PlatformURL string `mapstructure:"platform_url" yaml:"platform_url"`

	// PlatformEgress lists the always-allowed egress targets for connector
	// sandboxes: the platform endpoints plus the package registries the
	// runner fetches vendors from (registry.npmjs.org, pypi.org, …).
	PlatformEgress []SandboxEgressRule `mapstructure:"platform_egress" yaml:"platform_egress"`

	// VCPU / Memory bound each connector sandbox. Defaults: 1 vCPU, 512Mi.
	VCPU   int32  `mapstructure:"vcpu" yaml:"vcpu"`
	Memory string `mapstructure:"memory" yaml:"memory"`
}

// SandboxEgressRule is one host+port egress allow-list entry.
type SandboxEgressRule struct {
	Host string `mapstructure:"host" yaml:"host"`
	Port uint32 `mapstructure:"port" yaml:"port"`
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
	// Connector launch config is optional, but when a runner image is set the
	// companion fields become required — a bridge with no platform URL or no
	// egress to the control plane can never come up.
	if c.Connector.RunnerImage != "" {
		if c.Connector.PlatformURL == "" {
			return fmt.Errorf("sandbox.connector.platform_url is required when sandbox.connector.runner_image is set")
		}
		if len(c.Connector.PlatformEgress) == 0 {
			return fmt.Errorf("sandbox.connector.platform_egress is required when sandbox.connector.runner_image is set")
		}
		for i, e := range c.Connector.PlatformEgress {
			if e.Host == "" || e.Port == 0 {
				return fmt.Errorf("sandbox.connector.platform_egress[%d]: host and port are required", i)
			}
		}
	}
	return nil
}
