// Package sandboxed implements the Gibson harness's sandboxed tool execution
// backend: per-call Setec microVM dispatch via gRPC with mTLS.
//
// Scope:
//   - No Setec-specific gRPC client type leaks out of this package.
//   - All public types are plain structs that the daemon's startup wiring
//     populates from configuration.
//   - The Executor consumes a minimal SandboxClient interface so unit tests
//     can mock the gRPC surface without importing the Setec module.
//
// Dispatch is opt-in per tool: CallToolProto consults Registry.Lookup(name)
// and only routes through Executor.Execute when the lookup hits. A miss
// falls through to the existing local / component-registry / work-queue
// dispatch paths unchanged.
package sandboxed

import (
	"fmt"
	"sync"

	"github.com/zero-day-ai/gibson/internal/config"
)

// Registry holds the daemon's static map of sandboxed tools, keyed by tool
// name. It is built once at daemon startup from the SandboxConfig and is
// read-only afterwards.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]ToolSpec
}

// ToolSpec is the resolved, validated launch spec for a sandboxed tool.
// It is the internal (non-config) projection of config.SandboxToolConfig.
type ToolSpec struct {
	Image     string
	Command   []string
	Env       map[string]string
	VCPU      int32
	Memory    string
}

// NewRegistryFromConfig builds a Registry from a validated SandboxConfig.
// Returns an error if any tool entry is missing required fields — the daemon
// startup should treat this as fatal.
func NewRegistryFromConfig(cfg config.SandboxConfig) (*Registry, error) {
	r := &Registry{tools: make(map[string]ToolSpec, len(cfg.Tools))}
	for name, t := range cfg.Tools {
		if t.Image == "" {
			return nil, fmt.Errorf("sandbox.tools[%q]: image is required", name)
		}
		if len(t.Command) == 0 {
			return nil, fmt.Errorf("sandbox.tools[%q]: command must have at least one element", name)
		}
		if t.Resources.VCPU <= 0 {
			return nil, fmt.Errorf("sandbox.tools[%q]: resources.vcpu must be > 0", name)
		}
		if t.Resources.Memory == "" {
			return nil, fmt.Errorf("sandbox.tools[%q]: resources.memory is required", name)
		}
		r.tools[name] = ToolSpec{
			Image:   t.Image,
			Command: append([]string(nil), t.Command...),
			Env:     copyEnv(t.Env),
			VCPU:    t.Resources.VCPU,
			Memory:  t.Resources.Memory,
		}
	}
	return r, nil
}

// Lookup returns the ToolSpec for a tool name. The boolean is false if the
// tool is not registered for sandboxed execution — callers treat this as a
// soft miss and fall through to other dispatch paths.
func (r *Registry) Lookup(name string) (ToolSpec, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	spec, ok := r.tools[name]
	return spec, ok
}

// Size returns the number of sandboxed tools registered. Used for diagnostic
// logging at daemon startup.
func (r *Registry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tools)
}

func copyEnv(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
