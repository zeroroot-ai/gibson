package sandboxed

import (
	"strings"
	"testing"

	"github.com/zero-day-ai/gibson/internal/config"
)

func TestNewRegistryFromConfig_ValidTools(t *testing.T) {
	cfg := config.SandboxConfig{
		Tools: map[string]config.SandboxToolConfig{
			"hello": {
				Image:   "ghcr.io/zero-day-ai/gibson-tool-runner:hello-dev",
				Command: []string{"/tool-runner"},
				Env:     map[string]string{"FOO": "bar"},
				Resources: config.SandboxToolResources{VCPU: 1, Memory: "128Mi"},
			},
		},
	}
	r, err := NewRegistryFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewRegistryFromConfig: %v", err)
	}
	spec, ok := r.Lookup("hello")
	if !ok {
		t.Fatalf("expected 'hello' to be registered")
	}
	if spec.Image != cfg.Tools["hello"].Image {
		t.Errorf("image = %q; want %q", spec.Image, cfg.Tools["hello"].Image)
	}
	if len(spec.Command) != 1 || spec.Command[0] != "/tool-runner" {
		t.Errorf("command = %v; want [/tool-runner]", spec.Command)
	}
	if spec.Env["FOO"] != "bar" {
		t.Errorf("env FOO = %q; want 'bar'", spec.Env["FOO"])
	}
	if r.Size() != 1 {
		t.Errorf("size = %d; want 1", r.Size())
	}
	if _, ok := r.Lookup("nonexistent"); ok {
		t.Errorf("Lookup(nonexistent) should return false")
	}
}

func TestNewRegistryFromConfig_RejectsMissingFields(t *testing.T) {
	cases := []struct {
		name    string
		tool    config.SandboxToolConfig
		wantMsg string
	}{
		{
			name:    "no image",
			tool:    config.SandboxToolConfig{Command: []string{"x"}, Resources: config.SandboxToolResources{VCPU: 1, Memory: "64Mi"}},
			wantMsg: "image is required",
		},
		{
			name:    "empty command",
			tool:    config.SandboxToolConfig{Image: "x", Command: nil, Resources: config.SandboxToolResources{VCPU: 1, Memory: "64Mi"}},
			wantMsg: "command must have at least one element",
		},
		{
			name:    "zero vcpu",
			tool:    config.SandboxToolConfig{Image: "x", Command: []string{"x"}, Resources: config.SandboxToolResources{VCPU: 0, Memory: "64Mi"}},
			wantMsg: "resources.vcpu must be > 0",
		},
		{
			name:    "empty memory",
			tool:    config.SandboxToolConfig{Image: "x", Command: []string{"x"}, Resources: config.SandboxToolResources{VCPU: 1, Memory: ""}},
			wantMsg: "resources.memory is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.SandboxConfig{Tools: map[string]config.SandboxToolConfig{"t": tc.tool}}
			_, err := NewRegistryFromConfig(cfg)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestRegistry_DefensiveCopy(t *testing.T) {
	cfg := config.SandboxConfig{
		Tools: map[string]config.SandboxToolConfig{
			"t": {
				Image:     "x",
				Command:   []string{"a", "b"},
				Env:       map[string]string{"K": "V"},
				Resources: config.SandboxToolResources{VCPU: 1, Memory: "64Mi"},
			},
		},
	}
	r, err := NewRegistryFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewRegistryFromConfig: %v", err)
	}
	// Mutate caller's config after registry construction.
	cfg.Tools["t"].Command[0] = "MUTATED"
	cfg.Tools["t"].Env["K"] = "MUTATED"
	spec, _ := r.Lookup("t")
	if spec.Command[0] != "a" {
		t.Errorf("registry command mutated: got %v", spec.Command)
	}
	if spec.Env["K"] != "V" {
		t.Errorf("registry env mutated: got %v", spec.Env)
	}
}
