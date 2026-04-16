package config

import (
	"fmt"
	"os"
	"time"

	"github.com/zero-day-ai/gibson/internal/component"
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
	Enabled bool                          `mapstructure:"enabled" yaml:"enabled"`
	Setec   SandboxSetecConfig            `mapstructure:"setec" yaml:"setec"`
	Tools   map[string]SandboxToolConfig  `mapstructure:"tools" yaml:"tools"`
}

// SandboxSetecConfig describes how to reach and authenticate to the Setec
// frontend that this daemon dispatches sandboxed tool calls into.
type SandboxSetecConfig struct {
	Address     string                 `mapstructure:"address" yaml:"address"`
	Tenant      string                 `mapstructure:"tenant" yaml:"tenant"`
	CallTimeout time.Duration          `mapstructure:"call_timeout" yaml:"call_timeout"`
	MTLS        component.TLSConfig    `mapstructure:"mtls" yaml:"mtls"`
}

// SandboxToolConfig maps a Gibson tool name to the OCI image + command + env
// + resources that Setec should launch for each invocation.
type SandboxToolConfig struct {
	Image     string                 `mapstructure:"image" yaml:"image"`
	Command   []string               `mapstructure:"command" yaml:"command"`
	Env       map[string]string      `mapstructure:"env,omitempty" yaml:"env,omitempty"`
	Resources SandboxToolResources   `mapstructure:"resources" yaml:"resources"`
}

// SandboxToolResources declares the Setec sandbox resource budget for a tool.
type SandboxToolResources struct {
	VCPU   int32  `mapstructure:"vcpu" yaml:"vcpu"`
	Memory string `mapstructure:"memory" yaml:"memory"`
}

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
	for name, tool := range c.Tools {
		if tool.Image == "" {
			return fmt.Errorf("sandbox.tools[%q].image is required", name)
		}
		if len(tool.Command) == 0 {
			return fmt.Errorf("sandbox.tools[%q].command must have at least one element", name)
		}
		if tool.Resources.VCPU <= 0 {
			return fmt.Errorf("sandbox.tools[%q].resources.vcpu must be > 0", name)
		}
		if tool.Resources.Memory == "" {
			return fmt.Errorf("sandbox.tools[%q].resources.memory is required", name)
		}
	}
	return nil
}
