// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package config

import (
	"fmt"
	"os"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
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
	Enabled bool                `mapstructure:"enabled" yaml:"enabled"`
	Setec   SandboxSetecConfig  `mapstructure:"setec" yaml:"setec"`
	Devbox  SandboxDevboxConfig `mapstructure:"devbox" yaml:"devbox"`
}

// SandboxDevboxConfig configures the SESSION sandbox a component's DevboxExec
// commands run inside (gibson#1183).
//
// A devbox differs from a tool launch in the one way that matters: it is
// launched once per (tenant, session_id) and KEPT, with a durable /workspace,
// so `git clone` and then `go build` see the same filesystem. Tool launches
// stay one microVM per call.
//
// Image is deployment policy, not a component's choice. A component that could
// name its own image would choose the contents of the sandbox it then executes
// in, which is not a decision the calling side gets to make.
type SandboxDevboxConfig struct {
	// Image is the OCI reference every session sandbox runs. Empty disables
	// DevboxExec — the RPC then answers Unavailable naming the reason, which
	// is honest, rather than launching something arbitrary.
	Image string `mapstructure:"image" yaml:"image"`

	// VCPU / Memory bound each session. Defaults: 2 vCPU, 4Gi — a devbox
	// compiles, so it is sized above a tool launch.
	VCPU   int32  `mapstructure:"vcpu" yaml:"vcpu"`
	Memory string `mapstructure:"memory" yaml:"memory"`

	// SandboxClass is the setec SandboxClass session launches name. Defaults
	// to DefaultDevboxSandboxClass.
	SandboxClass string `mapstructure:"sandbox_class" yaml:"sandbox_class"`

	// WorkspaceSize is the durable /workspace PVC size. Empty defers to the
	// setec operator default.
	WorkspaceSize string `mapstructure:"workspace_size" yaml:"workspace_size"`

	// Idle is the session lifetime setec enforces. This is the backstop
	// against a forgotten session pinning a PVC and a metal node forever, so
	// it is never sent as zero — the launch is refused instead. Defaults to
	// DefaultDevboxIdle.
	Idle time.Duration `mapstructure:"idle" yaml:"idle"`
}

// SandboxSetecConfig describes how to reach and authenticate to the Setec
// frontend that this daemon dispatches sandboxed tool calls into.
type SandboxSetecConfig struct {
	Address     string              `mapstructure:"address" yaml:"address"`
	Tenant      string              `mapstructure:"tenant" yaml:"tenant"`
	CallTimeout time.Duration       `mapstructure:"call_timeout" yaml:"call_timeout"`
	MTLS        component.TLSConfig `mapstructure:"mtls" yaml:"mtls"`

	// SandboxClass is the setec SandboxClass every tool and catalog launch
	// names. Defaults to DefaultSandboxClass. It is never sent empty: an
	// empty class defers to whichever class the cluster marks default, which
	// means gibson runs untrusted tool code under an isolation posture it
	// never chose (ADR-0052).
	SandboxClass string `mapstructure:"sandbox_class" yaml:"sandbox_class"`

	// AgentSandboxClass is the deployment-default setec SandboxClass an
	// ephemeral agent launch names when the catalog manifest omits one
	// (ADR-0016). It is distinct from the tool class: an agent runs a whole
	// mission and gets its own isolation and egress posture (gVisor by
	// default in production). Defaults to DefaultAgentSandboxClass. The
	// per-agent manifest (gibson#1597) overrides it per launch.
	AgentSandboxClass string `mapstructure:"agent_sandbox_class" yaml:"agent_sandbox_class"`

	// AgentRunTimeout bounds one ephemeral agent mission run. An agent runs a
	// whole mission, so this is far longer than CallTimeout. Zero defers to
	// the launcher default (30m).
	AgentRunTimeout time.Duration `mapstructure:"agent_run_timeout" yaml:"agent_run_timeout"`
}

// SandboxClass names gibson requests from setec. These match the classes the
// setec chart ships (charts/setec/values.yaml `sandboxClasses`) from setec
// v0.107.0 onward: `tool` carries the external-only egress posture tool
// launches need, `connector` is deny-all until the launch declares its
// allow-list. An install that publishes classes under different names must
// override sandbox.setec.sandbox_class / sandbox.connector.sandbox_class —
// setec's Sandbox admission webhook rejects a launch naming a class that does
// not exist, so a mismatch fails closed at launch rather than silently
// downgrading isolation.
const (
	DefaultSandboxClass = "tool"

	// DefaultDevboxSandboxClass is the class session sandboxes name. It is
	// deliberately distinct from `tool`: a devbox is long-lived and holds a
	// durable volume, so an operator must be able to give it its own resource
	// ceiling and egress posture without touching tool launches.
	DefaultDevboxSandboxClass = "devbox"

	// DefaultAgentSandboxClass is the class an ephemeral agent launch names
	// when the catalog manifest omits one (ADR-0016). It is deliberately
	// distinct from `tool` and `devbox`: a code-executing agent gets its own
	// isolation backend (gVisor by default) and egress posture.
	DefaultAgentSandboxClass = "agent"

	// DefaultDevboxIdle bounds a session. Long enough for a working session,
	// short enough that a forgotten one does not hold metal overnight.
	DefaultDevboxIdle = 4 * time.Hour
)

// SandboxToolConfig / SandboxToolResources were removed under the
// gibson-tool-runner spec (task 16). Per-tool dispatch metadata now lives
// exclusively in the kind:tool catalog manifests embedded in the daemon
// image (ADR-0017, internal/platform/componentcatalog/manifests). A tool is
// added by publishing a manifest, not by editing config: the manifest is the
// single source of truth for the image digest, command and resources.

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
	if c.Setec.SandboxClass == "" {
		c.Setec.SandboxClass = DefaultSandboxClass
	}
	if c.Setec.AgentSandboxClass == "" {
		c.Setec.AgentSandboxClass = DefaultAgentSandboxClass
	}
	// Devbox defaults apply only when an image is configured. With no image
	// there is no session surface at all, and defaulting the rest would
	// suggest otherwise.
	if c.Devbox.Image != "" {
		if c.Devbox.SandboxClass == "" {
			c.Devbox.SandboxClass = DefaultDevboxSandboxClass
		}
		if c.Devbox.VCPU <= 0 {
			c.Devbox.VCPU = 2
		}
		if c.Devbox.Memory == "" {
			c.Devbox.Memory = "4Gi"
		}
		if c.Devbox.Idle <= 0 {
			c.Devbox.Idle = DefaultDevboxIdle
		}
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
