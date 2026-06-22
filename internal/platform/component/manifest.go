package component

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RuntimeType represents the runtime environment type for a component.
type RuntimeType string

const (
	RuntimeTypeGo     RuntimeType = "go"
	RuntimeTypePython RuntimeType = "python"
	RuntimeTypeNode   RuntimeType = "node"
	RuntimeTypeDocker RuntimeType = "docker"
	RuntimeTypeBinary RuntimeType = "binary"
	RuntimeTypeHTTP   RuntimeType = "http"
	RuntimeTypeGRPC   RuntimeType = "grpc"
)

// String returns the string representation of the RuntimeType.
func (r RuntimeType) String() string {
	return string(r)
}

// IsValid checks if the RuntimeType is a valid enum value.
func (r RuntimeType) IsValid() bool {
	switch r {
	case RuntimeTypeGo, RuntimeTypePython, RuntimeTypeNode, RuntimeTypeDocker,
		RuntimeTypeBinary, RuntimeTypeHTTP, RuntimeTypeGRPC:
		return true
	default:
		return false
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (r RuntimeType) MarshalJSON() ([]byte, error) {
	if !r.IsValid() {
		return nil, fmt.Errorf("invalid runtime type: %s", r)
	}
	return json.Marshal(string(r))
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (r *RuntimeType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	parsed, err := ParseRuntimeType(s)
	if err != nil {
		return err
	}

	*r = parsed
	return nil
}

// AllRuntimeTypes returns a slice containing all valid RuntimeType values.
func AllRuntimeTypes() []RuntimeType {
	return []RuntimeType{
		RuntimeTypeGo,
		RuntimeTypePython,
		RuntimeTypeNode,
		RuntimeTypeDocker,
		RuntimeTypeBinary,
		RuntimeTypeHTTP,
		RuntimeTypeGRPC,
	}
}

// ParseRuntimeType parses a string into a RuntimeType, returning an error if invalid.
func ParseRuntimeType(s string) (RuntimeType, error) {
	r := RuntimeType(s)
	if !r.IsValid() {
		return "", fmt.Errorf("invalid runtime type: %s", s)
	}
	return r, nil
}

// HealthCheckProtocol represents the protocol used for health checks.
type HealthCheckProtocol string

const (
	// HealthCheckProtocolHTTP uses HTTP GET requests for health checks
	HealthCheckProtocolHTTP HealthCheckProtocol = "http"

	// HealthCheckProtocolGRPC uses gRPC health checking protocol (grpc_health_v1)
	HealthCheckProtocolGRPC HealthCheckProtocol = "grpc"

	// HealthCheckProtocolAuto automatically detects the protocol (tries gRPC first, then HTTP)
	HealthCheckProtocolAuto HealthCheckProtocol = "auto"
)

// String returns the string representation of the HealthCheckProtocol.
func (p HealthCheckProtocol) String() string {
	return string(p)
}

// IsValid checks if the HealthCheckProtocol is a valid enum value.
func (p HealthCheckProtocol) IsValid() bool {
	switch p {
	case HealthCheckProtocolHTTP, HealthCheckProtocolGRPC, HealthCheckProtocolAuto, "":
		return true
	default:
		return false
	}
}

// AllHealthCheckProtocols returns a slice containing all valid HealthCheckProtocol values.
func AllHealthCheckProtocols() []HealthCheckProtocol {
	return []HealthCheckProtocol{
		HealthCheckProtocolHTTP,
		HealthCheckProtocolGRPC,
		HealthCheckProtocolAuto,
	}
}

// HealthCheckConfig configures health check behavior for a component.
// This allows components to specify how Gibson should verify their health
// during startup and ongoing monitoring.
type HealthCheckConfig struct {
	// Protocol specifies the health check protocol: "http", "grpc", or "auto" (default).
	// When set to "auto", Gibson will try gRPC first, then fall back to HTTP.
	Protocol HealthCheckProtocol `json:"protocol,omitempty" yaml:"protocol,omitempty"`

	// Interval between health checks during monitoring.
	// Default: 10 seconds
	Interval time.Duration `json:"interval,omitempty" yaml:"interval,omitempty"`

	// Timeout for individual health check requests.
	// Default: 5 seconds
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`

	// Endpoint path for HTTP health checks.
	// Default: "/health"
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`

	// ServiceName for gRPC health checks.
	// Default: "" (empty string checks overall server health)
	ServiceName string `json:"service_name,omitempty" yaml:"service_name,omitempty"`
}

// GetProtocol returns the health check protocol, defaulting to "auto" if not set.
func (h *HealthCheckConfig) GetProtocol() HealthCheckProtocol {
	if h == nil || h.Protocol == "" {
		return HealthCheckProtocolAuto
	}
	return h.Protocol
}

// GetInterval returns the health check interval, defaulting to 10 seconds if not set.
func (h *HealthCheckConfig) GetInterval() time.Duration {
	if h == nil || h.Interval == 0 {
		return 10 * time.Second
	}
	return h.Interval
}

// GetTimeout returns the health check timeout, defaulting to 5 seconds if not set.
func (h *HealthCheckConfig) GetTimeout() time.Duration {
	if h == nil || h.Timeout == 0 {
		return 5 * time.Second
	}
	return h.Timeout
}

// GetEndpoint returns the HTTP health check endpoint, defaulting to "/health" if not set.
func (h *HealthCheckConfig) GetEndpoint() string {
	if h == nil || h.Endpoint == "" {
		return "/health"
	}
	return h.Endpoint
}

// GetServiceName returns the gRPC service name for health checks.
// Empty string means check overall server health.
func (h *HealthCheckConfig) GetServiceName() string {
	if h == nil {
		return ""
	}
	return h.ServiceName
}

// Validate validates the HealthCheckConfig fields.
func (h *HealthCheckConfig) Validate() error {
	if h == nil {
		return nil
	}

	// Validate protocol
	if !h.Protocol.IsValid() {
		return fmt.Errorf("invalid health check protocol: %s (must be 'http', 'grpc', or 'auto')", h.Protocol)
	}

	// Validate interval (must be positive if set)
	if h.Interval < 0 {
		return fmt.Errorf("health check interval must be positive, got %v", h.Interval)
	}

	// Validate timeout (must be positive if set)
	if h.Timeout < 0 {
		return fmt.Errorf("health check timeout must be positive, got %v", h.Timeout)
	}

	return nil
}

// ContentEntry represents a component or manifest included in a repository.
// Used by repository manifests to declare their contents.
type ContentEntry struct {
	Kind string `json:"kind" yaml:"kind"` // Type of component (agent, tool, plugin, repository)
	Path string `json:"path" yaml:"path"` // Path to component manifest relative to repository root
}

// Manifest represents the metadata and configuration for a component.
// It defines how the component should be built, run, and integrated.
// The component kind (agent, tool, plugin) is determined by the CLI subcommand used,
// not by the manifest. Repositories should contain only one type of component.
type Manifest struct {
	Kind         string                 `json:"kind,omitempty" yaml:"kind,omitempty"`                 // Kind of manifest (component, repository)
	Name         string                 `json:"name" yaml:"name"`                                     // Component name
	Version      string                 `json:"version" yaml:"version"`                               // Semantic version (e.g., 1.0.0)
	Description  string                 `json:"description,omitempty" yaml:"description,omitempty"`   // Brief description
	Author       string                 `json:"author,omitempty" yaml:"author,omitempty"`             // Author name or organization
	License      string                 `json:"license,omitempty" yaml:"license,omitempty"`           // License identifier (e.g., MIT, Apache-2.0)
	Repository   string                 `json:"repository,omitempty" yaml:"repository,omitempty"`     // Source repository URL
	Capabilities []string               `json:"capabilities,omitempty" yaml:"capabilities,omitempty"` // Component capabilities (features, supported operations)
	Build        *BuildConfig           `json:"build,omitempty" yaml:"build,omitempty"`               // Build configuration
	Runtime      *RuntimeConfig         `json:"runtime,omitempty" yaml:"runtime,omitempty"`           // Runtime configuration (optional for repositories)
	Dependencies *ComponentDependencies `json:"dependencies,omitempty" yaml:"dependencies,omitempty"` // Component dependencies
	Contents     []ContentEntry         `json:"contents,omitempty" yaml:"contents,omitempty"`         // Repository contents (for repository manifests)
	Discover     bool                   `json:"discover,omitempty" yaml:"discover,omitempty"`         // Auto-discover components in repository
	Taxonomy     *TaxonomyExtension     `json:"taxonomy,omitempty" yaml:"taxonomy,omitempty"`         // Custom GraphRAG taxonomy extensions

	// SignalTags is an optional opt-in declaration of the free-form tag
	// keys this component stamps onto compliance signals via
	// `compliance.WithCustom` (agents) or proto field 99 (tools).
	// Used by the daemon to log DEBUG warnings when a component emits a
	// key it did not declare, helping operators catch tag drift.
	//
	// Example:
	//   signal_tags:
	//     - gitlab_project_id
	//     - gitlab_branch
	//     - change_ticket
	//
	// Leaving this empty means "no declared tags" — emissions are still
	// allowed, they just don't get an "expected key" cross-check.
	// Audit-metadata-riders spec Requirement 7.1.
	SignalTags []string `json:"signal_tags,omitempty" yaml:"signal_tags,omitempty"`
}

// BuildConfig contains build configuration for the component.
// Used for components that need to be compiled or packaged before running.
type BuildConfig struct {
	Command    string            `json:"command,omitempty" yaml:"command,omitempty"`       // Build command (e.g., "go build")
	Artifacts  []string          `json:"artifacts,omitempty" yaml:"artifacts,omitempty"`   // Build output paths
	Env        map[string]string `json:"env,omitempty" yaml:"env,omitempty"`               // Environment variables for build
	WorkDir    string            `json:"workdir,omitempty" yaml:"workdir,omitempty"`       // Working directory for build
	Context    string            `json:"context,omitempty" yaml:"context,omitempty"`       // Build context path
	Dockerfile string            `json:"dockerfile,omitempty" yaml:"dockerfile,omitempty"` // Dockerfile path for Docker builds
}

// RuntimeConfig contains runtime configuration for the component.
// Defines how the component should be executed.
type RuntimeConfig struct {
	Type        RuntimeType        `json:"type" yaml:"type"`                                     // Runtime type (go, python, docker, etc.)
	Entrypoint  string             `json:"entrypoint" yaml:"entrypoint"`                         // Executable path or command
	Args        []string           `json:"args,omitempty" yaml:"args,omitempty"`                 // Command-line arguments
	Env         map[string]string  `json:"env,omitempty" yaml:"env,omitempty"`                   // Environment variables
	WorkDir     string             `json:"workdir,omitempty" yaml:"workdir,omitempty"`           // Working directory
	Port        int                `json:"port,omitempty" yaml:"port,omitempty"`                 // Network port for HTTP/gRPC
	HealthURL   string             `json:"health_url,omitempty" yaml:"health_url,omitempty"`     // Health check endpoint (deprecated: use HealthCheck.Endpoint)
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty" yaml:"health_check,omitempty"` // Health check configuration
	Image       string             `json:"image,omitempty" yaml:"image,omitempty"`               // Docker image for container runtime
	Volumes     []string           `json:"volumes,omitempty" yaml:"volumes,omitempty"`           // Volume mounts for Docker
}

// ComponentDependencies defines dependencies required by the component.
// Used for dependency validation and version compatibility checks.
type ComponentDependencies struct {
	Gibson     string            `json:"gibson,omitempty" yaml:"gibson,omitempty"`         // Gibson framework version requirement
	Components []string          `json:"components,omitempty" yaml:"components,omitempty"` // Other component dependencies (name@version)
	System     []string          `json:"system,omitempty" yaml:"system,omitempty"`         // System dependencies (e.g., docker, python3)
	Env        map[string]string `json:"env,omitempty" yaml:"env,omitempty"`               // Required environment variables
}

// LoadManifest loads a component manifest from a file path.
// Supports both JSON and YAML formats based on file extension.
// Returns an error if the file doesn't exist, can't be read, or is invalid.
func LoadManifest(path string) (*Manifest, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, NewManifestNotFoundError(path)
	}

	// Read file contents
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, WrapComponentError(ErrCodeLoadFailed, "failed to read manifest file", err)
	}

	// Parse based on file extension
	ext := strings.ToLower(filepath.Ext(path))
	var manifest Manifest

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &manifest); err != nil {
			return nil, NewInvalidManifestError("failed to parse JSON manifest", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &manifest); err != nil {
			return nil, NewInvalidManifestError("failed to parse YAML manifest", err)
		}
	default:
		return nil, NewInvalidManifestError(
			fmt.Sprintf("unsupported manifest format: %s (must be .json, .yaml, or .yml)", ext),
			nil,
		)
	}

	// Validate the loaded manifest
	if err := manifest.Validate(); err != nil {
		return nil, NewInvalidManifestError("manifest validation failed", err)
	}

	return &manifest, nil
}

// Validate validates the Manifest fields.
// Returns an error if required fields are missing or values are invalid.
func (m *Manifest) Validate() error {
	// Validate name
	if m.Name == "" {
		return fmt.Errorf("component name is required")
	}
	if !isValidComponentName(m.Name) {
		return fmt.Errorf("invalid component name: %s (must contain only alphanumeric, dash, underscore)", m.Name)
	}

	// Validate version
	if m.Version == "" {
		return fmt.Errorf("component version is required")
	}
	if !isValidSemanticVersion(m.Version) {
		return fmt.Errorf("invalid version format: %s (must be semantic version like 1.0.0)", m.Version)
	}

	// Ensure capabilities is initialized to empty slice if nil
	if m.Capabilities == nil {
		m.Capabilities = []string{}
	}

	// Validate runtime config if present (optional for repository manifests)
	if m.Runtime != nil {
		if err := m.Runtime.Validate(); err != nil {
			return fmt.Errorf("runtime config validation failed: %w", err)
		}
	}

	// Validate build config if present
	if m.Build != nil {
		if err := m.Build.Validate(); err != nil {
			return fmt.Errorf("build config validation failed: %w", err)
		}
	}

	// Validate dependencies if present
	if m.Dependencies != nil {
		if err := m.Dependencies.Validate(); err != nil {
			return fmt.Errorf("dependencies validation failed: %w", err)
		}
	}

	// Validate taxonomy if present
	if m.Taxonomy != nil {
		if err := m.Taxonomy.Validate(); err != nil {
			return fmt.Errorf("taxonomy validation failed: %w", err)
		}
	}

	return nil
}

// Validate validates the BuildConfig fields.
func (b *BuildConfig) Validate() error {
	if b.Command == "" && b.Dockerfile == "" {
		return fmt.Errorf("either build command or dockerfile is required")
	}

	// Validate Docker-specific fields
	if b.Dockerfile != "" {
		if b.Context == "" {
			return fmt.Errorf("build context is required when dockerfile is specified")
		}
	}

	return nil
}

// Validate validates the RuntimeConfig fields.
func (r *RuntimeConfig) Validate() error {
	// Validate runtime type
	if !r.Type.IsValid() {
		return fmt.Errorf("invalid runtime type: %s", r.Type)
	}

	// Validate entrypoint
	if r.Entrypoint == "" {
		return fmt.Errorf("runtime entrypoint is required")
	}

	// Validate port for network-based runtimes
	if r.Type == RuntimeTypeHTTP || r.Type == RuntimeTypeGRPC {
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("port must be between 1 and 65535 for %s runtime, got %d", r.Type, r.Port)
		}
	}

	// Validate Docker-specific fields
	if r.Type == RuntimeTypeDocker {
		if r.Image == "" {
			return fmt.Errorf("docker image is required for docker runtime")
		}
	}

	// Validate health check config if present
	if r.HealthCheck != nil {
		if err := r.HealthCheck.Validate(); err != nil {
			return fmt.Errorf("health check config validation failed: %w", err)
		}
	}

	return nil
}

// Validate validates the ComponentDependencies fields.
func (d *ComponentDependencies) Validate() error {
	// Validate Gibson version if specified
	if d.Gibson != "" {
		if !isValidVersionConstraint(d.Gibson) {
			return fmt.Errorf("invalid Gibson version constraint: %s", d.Gibson)
		}
	}

	// Validate component dependencies
	for _, dep := range d.Components {
		if !isValidDependency(dep) {
			return fmt.Errorf("invalid component dependency format: %s (must be name@version)", dep)
		}
	}

	return nil
}

// Helper functions for validation

// isValidComponentName checks if a component name is valid.
// Valid names contain only alphanumeric characters, dashes, and underscores.
func isValidComponentName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// isValidSemanticVersion checks if a version string follows semantic versioning.
// Accepts formats like: 1.0.0, 1.0.0-alpha, 1.0.0+build
func isValidSemanticVersion(version string) bool {
	if version == "" {
		return false
	}
	// Simple validation - just check for basic pattern
	parts := strings.Split(strings.Split(version, "+")[0], "-")
	versionParts := strings.Split(parts[0], ".")
	if len(versionParts) < 2 || len(versionParts) > 3 {
		return false
	}
	for _, part := range versionParts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// isValidVersionConstraint checks if a version constraint is valid.
// Accepts formats like: >=1.0.0, ~1.2.0, ^1.0.0, 1.0.0
func isValidVersionConstraint(constraint string) bool {
	if constraint == "" {
		return false
	}
	// Remove constraint operators
	version := strings.TrimPrefix(constraint, ">=")
	version = strings.TrimPrefix(version, "<=")
	version = strings.TrimPrefix(version, ">")
	version = strings.TrimPrefix(version, "<")
	version = strings.TrimPrefix(version, "~")
	version = strings.TrimPrefix(version, "^")
	version = strings.TrimSpace(version)

	return isValidSemanticVersion(version)
}

// isValidDependency checks if a dependency string is valid.
// Valid format: name@version (e.g., mycomponent@1.0.0)
func isValidDependency(dep string) bool {
	if dep == "" {
		return false
	}
	parts := strings.Split(dep, "@")
	if len(parts) != 2 {
		return false
	}
	return isValidComponentName(parts[0]) && isValidVersionConstraint(parts[1])
}

// GetBuildArtifacts returns the list of build artifacts.
// If no artifacts are specified, returns a default based on runtime type.
func (b *BuildConfig) GetBuildArtifacts() []string {
	if len(b.Artifacts) > 0 {
		return b.Artifacts
	}
	return []string{}
}

// GetEnv returns the environment variables for the build.
// Returns an empty map if no env vars are specified.
func (b *BuildConfig) GetEnv() map[string]string {
	if b.Env == nil {
		return make(map[string]string)
	}
	return b.Env
}

// GetEnv returns the environment variables for the runtime.
// Returns an empty map if no env vars are specified.
func (r *RuntimeConfig) GetEnv() map[string]string {
	if r.Env == nil {
		return make(map[string]string)
	}
	return r.Env
}

// GetArgs returns the command-line arguments.
// Returns an empty slice if no args are specified.
func (r *RuntimeConfig) GetArgs() []string {
	if r.Args == nil {
		return []string{}
	}
	return r.Args
}

// GetVolumes returns the volume mounts for Docker.
// Returns an empty slice if no volumes are specified.
func (r *RuntimeConfig) GetVolumes() []string {
	if r.Volumes == nil {
		return []string{}
	}
	return r.Volumes
}

// IsNetworkBased returns true if the runtime type requires network communication.
func (r *RuntimeConfig) IsNetworkBased() bool {
	return r.Type == RuntimeTypeHTTP || r.Type == RuntimeTypeGRPC
}

// IsContainerBased returns true if the runtime type uses containers.
func (r *RuntimeConfig) IsContainerBased() bool {
	return r.Type == RuntimeTypeDocker
}

// GetHealthCheckConfig returns the health check configuration.
// Returns a default config if none is specified.
func (r *RuntimeConfig) GetHealthCheckConfig() *HealthCheckConfig {
	if r.HealthCheck != nil {
		return r.HealthCheck
	}
	// Return default config
	return &HealthCheckConfig{}
}

// GetComponents returns the list of component dependencies.
func (d *ComponentDependencies) GetComponents() []string {
	if d.Components == nil {
		return []string{}
	}
	return d.Components
}

// GetSystem returns the list of system dependencies.
func (d *ComponentDependencies) GetSystem() []string {
	if d.System == nil {
		return []string{}
	}
	return d.System
}

// GetEnv returns the required environment variables.
func (d *ComponentDependencies) GetEnv() map[string]string {
	if d.Env == nil {
		return make(map[string]string)
	}
	return d.Env
}

// HasDependencies returns true if any dependencies are specified.
func (d *ComponentDependencies) HasDependencies() bool {
	return d.Gibson != "" || len(d.Components) > 0 || len(d.System) > 0 || len(d.Env) > 0
}

// TaxonomyExtension defines custom GraphRAG taxonomy extensions for a component.
// Agents can extend the taxonomy with custom node types and relationships.
type TaxonomyExtension struct {
	NodeTypes     []NodeTypeExtension     `json:"node_types,omitempty" yaml:"node_types,omitempty"`
	Relationships []RelationshipExtension `json:"relationships,omitempty" yaml:"relationships,omitempty"`
}

// NodeTypeExtension defines a custom node type for the taxonomy.
type NodeTypeExtension struct {
	Name        string              `json:"name" yaml:"name"`
	Category    string              `json:"category,omitempty" yaml:"category,omitempty"`
	Description string              `json:"description,omitempty" yaml:"description,omitempty"`
	Properties  []PropertyExtension `json:"properties,omitempty" yaml:"properties,omitempty"`
}

// PropertyExtension defines a property for a node type extension.
type PropertyExtension struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type,omitempty" yaml:"type,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// RelationshipExtension defines a custom relationship type for the taxonomy.
type RelationshipExtension struct {
	Name        string   `json:"name" yaml:"name"`
	Category    string   `json:"category,omitempty" yaml:"category,omitempty"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	FromTypes   []string `json:"from_types,omitempty" yaml:"from_types,omitempty"`
	ToTypes     []string `json:"to_types,omitempty" yaml:"to_types,omitempty"`
}

// Validate validates the TaxonomyExtension fields.
func (t *TaxonomyExtension) Validate() error {
	// Validate node types
	for i, nt := range t.NodeTypes {
		if nt.Name == "" {
			return fmt.Errorf("node type at index %d has no name", i)
		}
	}

	// Validate relationships
	for i, rel := range t.Relationships {
		if rel.Name == "" {
			return fmt.Errorf("relationship at index %d has no name", i)
		}
	}

	return nil
}
