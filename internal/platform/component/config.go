package component

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ComponentConfig represents the configuration for a single component.
// It defines how a component should be loaded and initialized.
type ComponentConfig struct {
	// Name is the unique identifier for the component.
	Name string `yaml:"name" json:"name"`

	// Source indicates where the component originates from.
	// Valid values: internal, external, remote, config
	Source ComponentSource `yaml:"source" json:"source"`

	// Path is the file system path to the component (required for external components).
	Path string `yaml:"path,omitempty" json:"path,omitempty"`

	// Repo is the repository URL for remote components (required for remote components).
	Repo string `yaml:"repo,omitempty" json:"repo,omitempty"`

	// Branch specifies the git branch to use for remote components.
	Branch string `yaml:"branch,omitempty" json:"branch,omitempty"`

	// Tag specifies the git tag to use for remote components.
	Tag string `yaml:"tag,omitempty" json:"tag,omitempty"`

	// Settings contains component-specific configuration as key-value pairs.
	Settings map[string]interface{} `yaml:"settings,omitempty" json:"settings,omitempty"`

	// AutoStart indicates whether the component should start automatically.
	AutoStart bool `yaml:"auto_start,omitempty" json:"auto_start,omitempty"`
}

// ComponentsConfig represents the full components configuration.
// It organizes components by their kind (agents, tools, plugins).
type ComponentsConfig struct {
	// Agents contains the list of agent component configurations.
	Agents []ComponentConfig `yaml:"agents,omitempty" json:"agents,omitempty"`

	// Tools contains the list of tool component configurations.
	Tools []ComponentConfig `yaml:"tools,omitempty" json:"tools,omitempty"`

	// Plugins contains the list of plugin component configurations.
	Plugins []ComponentConfig `yaml:"plugins,omitempty" json:"plugins,omitempty"`
}

// Validate validates the ComponentConfig fields.
// Returns an error if required fields are missing or values are invalid.
func (c *ComponentConfig) Validate() error {
	// Validate name
	if c.Name == "" {
		return fmt.Errorf("component name is required")
	}
	if !isValidIdentifier(c.Name) {
		return fmt.Errorf("invalid component name: %s (must be a valid identifier: alphanumeric, dash, underscore, no leading digits)", c.Name)
	}

	// Validate source
	if !c.Source.IsValid() {
		return fmt.Errorf("invalid component source: %s (must be internal, external, remote, or config)", c.Source)
	}

	// Source-specific validation
	switch c.Source {
	case ComponentSourceExternal:
		if c.Path == "" {
			return fmt.Errorf("path is required for external components")
		}
	case ComponentSourceRemote:
		if c.Repo == "" {
			return fmt.Errorf("repo is required for remote components")
		}
		// Either branch or tag can be specified, but not both
		if c.Branch != "" && c.Tag != "" {
			return fmt.Errorf("cannot specify both branch and tag for remote components")
		}
	}

	return nil
}

// GetSettings returns the settings map, ensuring it's never nil.
func (c *ComponentConfig) GetSettings() map[string]interface{} {
	if c.Settings == nil {
		return make(map[string]interface{})
	}
	return c.Settings
}

// IsAutoStart returns whether the component should start automatically.
func (c *ComponentConfig) IsAutoStart() bool {
	return c.AutoStart
}

// Validate validates the ComponentsConfig.
// Returns an error if any component configuration is invalid.
func (cfg *ComponentsConfig) Validate() error {
	// Track component names to ensure uniqueness across all kinds
	names := make(map[string]bool)

	// Validate agents
	for i, agent := range cfg.Agents {
		if err := agent.Validate(); err != nil {
			return fmt.Errorf("invalid agent configuration at index %d: %w", i, err)
		}
		if names[agent.Name] {
			return fmt.Errorf("duplicate component name: %s", agent.Name)
		}
		names[agent.Name] = true
	}

	// Validate tools
	for i, tool := range cfg.Tools {
		if err := tool.Validate(); err != nil {
			return fmt.Errorf("invalid tool configuration at index %d: %w", i, err)
		}
		if names[tool.Name] {
			return fmt.Errorf("duplicate component name: %s", tool.Name)
		}
		names[tool.Name] = true
	}

	// Validate plugins
	for i, plugin := range cfg.Plugins {
		if err := plugin.Validate(); err != nil {
			return fmt.Errorf("invalid plugin configuration at index %d: %w", i, err)
		}
		if names[plugin.Name] {
			return fmt.Errorf("duplicate component name: %s", plugin.Name)
		}
		names[plugin.Name] = true
	}

	return nil
}

// AllComponents returns all component configurations across all kinds.
func (cfg *ComponentsConfig) AllComponents() []ComponentConfig {
	all := make([]ComponentConfig, 0, len(cfg.Agents)+len(cfg.Tools)+len(cfg.Plugins))
	all = append(all, cfg.Agents...)
	all = append(all, cfg.Tools...)
	all = append(all, cfg.Plugins...)
	return all
}

// ComponentsByKind returns component configurations for a specific kind.
func (cfg *ComponentsConfig) ComponentsByKind(kind ComponentKind) []ComponentConfig {
	switch kind {
	case ComponentKindAgent:
		return cfg.Agents
	case ComponentKindTool:
		return cfg.Tools
	case ComponentKindPlugin:
		return cfg.Plugins
	default:
		return []ComponentConfig{}
	}
}

// LoadComponentsFromConfig parses the components section from a YAML configuration.
// It validates each component and handles missing or invalid components gracefully.
// Invalid components are logged as warnings and skipped, allowing valid components to load.
//
// Parameters:
//   - data: YAML configuration data containing a "components" section
//   - logger: Optional logger for warnings (if nil, warnings are silently skipped)
//
// Returns:
//   - *ComponentsConfig: Validated component configurations
//   - error: Only returns error if the YAML is malformed or validation fails entirely
func LoadComponentsFromConfig(data []byte, logger Logger) (*ComponentsConfig, error) {
	// Parse the full YAML structure
	var rawConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &rawConfig); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Extract components section
	componentsData, ok := rawConfig["components"]
	if !ok {
		// No components section - return empty config (not an error)
		return &ComponentsConfig{}, nil
	}

	// Convert back to YAML for unmarshaling into ComponentsConfig
	componentsYAML, err := yaml.Marshal(componentsData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal components section: %w", err)
	}

	var cfg ComponentsConfig
	if err := yaml.Unmarshal(componentsYAML, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal components configuration: %w", err)
	}

	// Validate each component kind separately to handle errors gracefully
	cfg.Agents = validateAndFilterComponents(cfg.Agents, "agent", logger)
	cfg.Tools = validateAndFilterComponents(cfg.Tools, "tool", logger)
	cfg.Plugins = validateAndFilterComponents(cfg.Plugins, "plugin", logger)

	// Final validation to check for duplicate names across kinds
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("component configuration validation failed: %w", err)
	}

	return &cfg, nil
}

// Logger is an interface for logging warnings during component loading.
// This allows the caller to provide their own logger implementation.
type Logger interface {
	Warnf(format string, args ...interface{})
}

// validateAndFilterComponents validates a slice of component configs and filters out invalid ones.
// Invalid components are logged as warnings and removed from the result.
func validateAndFilterComponents(components []ComponentConfig, kindName string, logger Logger) []ComponentConfig {
	if len(components) == 0 {
		return components
	}

	valid := make([]ComponentConfig, 0, len(components))
	for i, comp := range components {
		if err := comp.Validate(); err != nil {
			if logger != nil {
				logger.Warnf("Skipping invalid %s component at index %d (%s): %v", kindName, i, comp.Name, err)
			}
			continue
		}
		valid = append(valid, comp)
	}

	return valid
}

// isValidIdentifier checks if a string is a valid identifier for a component name.
// Valid identifiers:
//   - Start with a letter or underscore
//   - Contain only letters, digits, underscores, and hyphens
//   - Are not empty
func isValidIdentifier(s string) bool {
	if s == "" {
		return false
	}

	// Regex: starts with letter or underscore, followed by alphanumeric, underscore, or hyphen
	identifierRegex := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)
	return identifierRegex.MatchString(s)
}

// ParseComponentSource is a convenience function to parse a string into a ComponentSource.
// It wraps the ParseComponentSource function from types.go.
func ParseComponentSourceString(s string) (ComponentSource, error) {
	return ParseComponentSource(s)
}

// GetComponentByName finds a component configuration by name across all kinds.
// Returns the component and true if found, or an empty config and false if not found.
func (cfg *ComponentsConfig) GetComponentByName(name string) (ComponentConfig, bool) {
	// Search in agents
	for _, agent := range cfg.Agents {
		if agent.Name == name {
			return agent, true
		}
	}

	// Search in tools
	for _, tool := range cfg.Tools {
		if tool.Name == name {
			return tool, true
		}
	}

	// Search in plugins
	for _, plugin := range cfg.Plugins {
		if plugin.Name == name {
			return plugin, true
		}
	}

	return ComponentConfig{}, false
}

// CountComponents returns the total number of components configured.
func (cfg *ComponentsConfig) CountComponents() int {
	return len(cfg.Agents) + len(cfg.Tools) + len(cfg.Plugins)
}

// CountAutoStart returns the number of components configured to auto-start.
func (cfg *ComponentsConfig) CountAutoStart() int {
	count := 0
	for _, comp := range cfg.AllComponents() {
		if comp.AutoStart {
			count++
		}
	}
	return count
}

// FilterBySource returns all components with the specified source.
func (cfg *ComponentsConfig) FilterBySource(source ComponentSource) []ComponentConfig {
	filtered := make([]ComponentConfig, 0)
	for _, comp := range cfg.AllComponents() {
		if comp.Source == source {
			filtered = append(filtered, comp)
		}
	}
	return filtered
}

// FilterByAutoStart returns all components configured to auto-start.
func (cfg *ComponentsConfig) FilterByAutoStart() []ComponentConfig {
	filtered := make([]ComponentConfig, 0)
	for _, comp := range cfg.AllComponents() {
		if comp.AutoStart {
			filtered = append(filtered, comp)
		}
	}
	return filtered
}

// MergeComponentsConfig merges another ComponentsConfig into this one.
// Components from the other config are appended to the existing ones.
// Note: This does not check for duplicate names; call Validate() after merging.
func (cfg *ComponentsConfig) MergeComponentsConfig(other *ComponentsConfig) {
	if other == nil {
		return
	}

	cfg.Agents = append(cfg.Agents, other.Agents...)
	cfg.Tools = append(cfg.Tools, other.Tools...)
	cfg.Plugins = append(cfg.Plugins, other.Plugins...)
}

// HasComponents returns true if any components are configured.
func (cfg *ComponentsConfig) HasComponents() bool {
	return len(cfg.Agents) > 0 || len(cfg.Tools) > 0 || len(cfg.Plugins) > 0
}

// NormalizeComponentName normalizes a component name by converting it to lowercase
// and replacing spaces with hyphens.
func NormalizeComponentName(name string) string {
	normalized := strings.ToLower(name)
	normalized = strings.ReplaceAll(normalized, " ", "-")
	normalized = strings.ReplaceAll(normalized, "_", "-")
	return normalized
}
