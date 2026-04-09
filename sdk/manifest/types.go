package manifest

// SDK manifest types for Gibson components.
// These types define the manifest structure for agents, tools, and plugins.

// AgentManifest represents the manifest for a Gibson agent.
type AgentManifest struct {
	Name         string            `json:"name" yaml:"name"`
	Version      string            `json:"version" yaml:"version"`
	Description  string            `json:"description,omitempty" yaml:"description,omitempty"`
	Author       string            `json:"author,omitempty" yaml:"author,omitempty"`
	License      string            `json:"license,omitempty" yaml:"license,omitempty"`
	Repository   string            `json:"repository,omitempty" yaml:"repository,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Runtime      *RuntimeConfig    `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	Dependencies *Dependencies     `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// ToolManifest represents the manifest for a Gibson tool.
type ToolManifest struct {
	Name         string            `json:"name" yaml:"name"`
	Version      string            `json:"version" yaml:"version"`
	Description  string            `json:"description,omitempty" yaml:"description,omitempty"`
	Author       string            `json:"author,omitempty" yaml:"author,omitempty"`
	License      string            `json:"license,omitempty" yaml:"license,omitempty"`
	Repository   string            `json:"repository,omitempty" yaml:"repository,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Runtime      *RuntimeConfig    `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	Dependencies *Dependencies     `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// PluginManifest represents the manifest for a Gibson plugin.
type PluginManifest struct {
	Name         string            `json:"name" yaml:"name"`
	Version      string            `json:"version" yaml:"version"`
	Description  string            `json:"description,omitempty" yaml:"description,omitempty"`
	Author       string            `json:"author,omitempty" yaml:"author,omitempty"`
	License      string            `json:"license,omitempty" yaml:"license,omitempty"`
	Repository   string            `json:"repository,omitempty" yaml:"repository,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Runtime      *RuntimeConfig    `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	Dependencies *Dependencies     `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// RuntimeConfig defines how the component should be executed.
type RuntimeConfig struct {
	Type       string            `json:"type" yaml:"type"`                           // go, python, node, docker, binary, http, grpc
	Entrypoint string            `json:"entrypoint" yaml:"entrypoint"`               // Executable path or command
	Args       []string          `json:"args,omitempty" yaml:"args,omitempty"`       // Command-line arguments
	Env        map[string]string `json:"env,omitempty" yaml:"env,omitempty"`         // Environment variables
	WorkDir    string            `json:"workdir,omitempty" yaml:"workdir,omitempty"` // Working directory
	Port       int               `json:"port,omitempty" yaml:"port,omitempty"`       // Network port for HTTP/gRPC
	Image      string            `json:"image,omitempty" yaml:"image,omitempty"`     // Docker image for container runtime
	Volumes    []string          `json:"volumes,omitempty" yaml:"volumes,omitempty"` // Volume mounts for Docker
}

// Dependencies defines dependencies required by the component.
type Dependencies struct {
	Gibson     string            `json:"gibson,omitempty" yaml:"gibson,omitempty"`         // Gibson framework version requirement
	Components []string          `json:"components,omitempty" yaml:"components,omitempty"` // Other component dependencies (name@version)
	System     []string          `json:"system,omitempty" yaml:"system,omitempty"`         // System dependencies (e.g., docker, python3)
	Env        map[string]string `json:"env,omitempty" yaml:"env,omitempty"`               // Required environment variables
}

// Validate validates the AgentManifest fields.
func (m *AgentManifest) Validate() error {
	if m.Name == "" {
		return ErrNameRequired
	}
	if m.Version == "" {
		return ErrVersionRequired
	}
	if m.Capabilities == nil {
		m.Capabilities = []string{}
	}
	return nil
}

// Validate validates the ToolManifest fields.
func (m *ToolManifest) Validate() error {
	if m.Name == "" {
		return ErrNameRequired
	}
	if m.Version == "" {
		return ErrVersionRequired
	}
	if m.Capabilities == nil {
		m.Capabilities = []string{}
	}
	return nil
}

// Validate validates the PluginManifest fields.
func (m *PluginManifest) Validate() error {
	if m.Name == "" {
		return ErrNameRequired
	}
	if m.Version == "" {
		return ErrVersionRequired
	}
	if m.Capabilities == nil {
		m.Capabilities = []string{}
	}
	return nil
}
