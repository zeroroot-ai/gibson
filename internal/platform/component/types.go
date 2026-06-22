package component

import (
	"encoding/json"
	"fmt"
	"time"
)

// ComponentKind represents the type of component.
type ComponentKind string

const (
	ComponentKindAgent      ComponentKind = "agent"
	ComponentKindTool       ComponentKind = "tool"
	ComponentKindPlugin     ComponentKind = "plugin"
	ComponentKindRepository ComponentKind = "repository"
)

// String returns the string representation of the ComponentKind.
func (k ComponentKind) String() string {
	return string(k)
}

// IsValid checks if the ComponentKind is a non-empty value.
// Any non-empty kind is considered valid.
func (k ComponentKind) IsValid() bool {
	return k != ""
}

// IsRepositoryKind returns true if the kind is repository.
func (k ComponentKind) IsRepositoryKind() bool {
	return k == ComponentKindRepository
}

// IsComponentKind returns true if the kind is agent, tool, or plugin (not repository).
func (k ComponentKind) IsComponentKind() bool {
	return k == ComponentKindAgent || k == ComponentKindTool || k == ComponentKindPlugin
}

// MarshalJSON implements the json.Marshaler interface.
func (k ComponentKind) MarshalJSON() ([]byte, error) {
	if !k.IsValid() {
		return nil, fmt.Errorf("invalid component kind: %s", k)
	}
	return json.Marshal(string(k))
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (k *ComponentKind) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	parsed, err := ParseComponentKind(s)
	if err != nil {
		return err
	}

	*k = parsed
	return nil
}

// AllComponentKinds returns a slice containing all valid ComponentKind values.
func AllComponentKinds() []ComponentKind {
	return []ComponentKind{
		ComponentKindAgent,
		ComponentKindTool,
		ComponentKindPlugin,
		ComponentKindRepository,
	}
}

// ParseComponentKind parses a string into a ComponentKind, returning an error if empty.
func ParseComponentKind(s string) (ComponentKind, error) {
	if s == "" {
		return "", fmt.Errorf("component kind cannot be empty")
	}
	return ComponentKind(s), nil
}

// ComponentSource represents where a component originates from.
type ComponentSource string

const (
	ComponentSourceInternal ComponentSource = "internal"
	ComponentSourceExternal ComponentSource = "external"
	ComponentSourceRemote   ComponentSource = "remote"
	ComponentSourceConfig   ComponentSource = "config"
)

// String returns the string representation of the ComponentSource.
func (s ComponentSource) String() string {
	return string(s)
}

// IsValid checks if the ComponentSource is a valid enum value.
func (s ComponentSource) IsValid() bool {
	switch s {
	case ComponentSourceInternal, ComponentSourceExternal, ComponentSourceRemote, ComponentSourceConfig:
		return true
	default:
		return false
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (s ComponentSource) MarshalJSON() ([]byte, error) {
	if !s.IsValid() {
		return nil, fmt.Errorf("invalid component source: %s", s)
	}
	return json.Marshal(string(s))
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *ComponentSource) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	parsed, err := ParseComponentSource(str)
	if err != nil {
		return err
	}

	*s = parsed
	return nil
}

// AllComponentSources returns a slice containing all valid ComponentSource values.
func AllComponentSources() []ComponentSource {
	return []ComponentSource{
		ComponentSourceInternal,
		ComponentSourceExternal,
		ComponentSourceRemote,
		ComponentSourceConfig,
	}
}

// ParseComponentSource parses a string into a ComponentSource, returning an error if invalid.
func ParseComponentSource(s string) (ComponentSource, error) {
	src := ComponentSource(s)
	if !src.IsValid() {
		return "", fmt.Errorf("invalid component source: %s", s)
	}
	return src, nil
}

// ComponentStatus represents the runtime status of a component.
type ComponentStatus string

const (
	ComponentStatusAvailable ComponentStatus = "available"
	ComponentStatusRunning   ComponentStatus = "running"
	ComponentStatusStopped   ComponentStatus = "stopped"
	ComponentStatusError     ComponentStatus = "error"
)

// String returns the string representation of the ComponentStatus.
func (s ComponentStatus) String() string {
	return string(s)
}

// IsValid checks if the ComponentStatus is a valid enum value.
func (s ComponentStatus) IsValid() bool {
	switch s {
	case ComponentStatusAvailable, ComponentStatusRunning, ComponentStatusStopped, ComponentStatusError:
		return true
	default:
		return false
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (s ComponentStatus) MarshalJSON() ([]byte, error) {
	if !s.IsValid() {
		return nil, fmt.Errorf("invalid component status: %s", s)
	}
	return json.Marshal(string(s))
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *ComponentStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	parsed, err := ParseComponentStatus(str)
	if err != nil {
		return err
	}

	*s = parsed
	return nil
}

// AllComponentStatuses returns a slice containing all valid ComponentStatus values.
func AllComponentStatuses() []ComponentStatus {
	return []ComponentStatus{
		ComponentStatusAvailable,
		ComponentStatusRunning,
		ComponentStatusStopped,
		ComponentStatusError,
	}
}

// ParseComponentStatus parses a string into a ComponentStatus, returning an error if invalid.
func ParseComponentStatus(s string) (ComponentStatus, error) {
	status := ComponentStatus(s)
	if !status.IsValid() {
		return "", fmt.Errorf("invalid component status: %s", s)
	}
	return status, nil
}

// Component represents an external component (agent, tool, or plugin) in the Gibson framework.
// Components can be internal (built-in), external (local binaries), remote (network services),
// or config-based (defined in configuration files).
type Component struct {
	ID        int64           `json:"id" db:"id"`                                                       // Database primary key
	Kind      ComponentKind   `json:"kind" yaml:"kind" db:"kind"`                                       // Type of component (agent, tool, plugin)
	Name      string          `json:"name" yaml:"name" db:"name"`                                       // Component name
	Version   string          `json:"version" yaml:"version" db:"version"`                              // Semantic version
	RepoPath  string          `json:"repo_path" db:"repo_path"`                                         // Path to cloned source repository in _repos/
	BinPath   string          `json:"bin_path" db:"bin_path"`                                           // Path to installed binary in bin/
	Source    ComponentSource `json:"source" yaml:"source" db:"source"`                                 // Where the component originates
	Status    ComponentStatus `json:"status" yaml:"status" db:"status"`                                 // Current runtime status
	Manifest  *Manifest       `json:"manifest,omitempty" yaml:"manifest,omitempty" db:"manifest"`       // Component manifest (stored as JSON in DB)
	Port      int             `json:"port,omitempty" yaml:"port,omitempty" db:"port"`                   // Network port for remote components
	PID       int             `json:"pid,omitempty" yaml:"pid,omitempty" db:"pid"`                      // Process ID for running components
	CreatedAt time.Time       `json:"created_at" yaml:"created_at" db:"created_at"`                     // When the component was registered
	UpdatedAt time.Time       `json:"updated_at" yaml:"updated_at" db:"updated_at"`                     // Last status update time
	StartedAt *time.Time      `json:"started_at,omitempty" yaml:"started_at,omitempty" db:"started_at"` // When the component started running
	StoppedAt *time.Time      `json:"stopped_at,omitempty" yaml:"stopped_at,omitempty" db:"stopped_at"` // When the component stopped
}

// Validate validates the Component fields.
// Returns an error if required fields are missing or values are invalid.
func (c *Component) Validate() error {
	if !c.Kind.IsValid() {
		return fmt.Errorf("invalid component kind: %s", c.Kind)
	}

	if c.Name == "" {
		return fmt.Errorf("component name is required")
	}

	if c.Version == "" {
		return fmt.Errorf("component version is required")
	}

	// Validate that either RepoPath or BinPath is set (or both)
	// Components need at least one path to be functional
	if c.RepoPath == "" && c.BinPath == "" {
		return fmt.Errorf("component must have either repo_path or bin_path set")
	}

	if !c.Source.IsValid() {
		return fmt.Errorf("invalid component source: %s", c.Source)
	}

	if !c.Status.IsValid() {
		return fmt.Errorf("invalid component status: %s", c.Status)
	}

	// Validate port for remote components
	if c.Source == ComponentSourceRemote {
		if c.Port < 1 || c.Port > 65535 {
			return fmt.Errorf("port must be between 1 and 65535 for remote components, got %d", c.Port)
		}
	}

	// Validate PID for running components
	if c.Status == ComponentStatusRunning {
		if c.PID < 1 {
			return fmt.Errorf("PID must be positive for running components, got %d", c.PID)
		}
		if c.StartedAt == nil {
			return fmt.Errorf("started_at is required for running components")
		}
	}

	// Validate manifest if present
	if c.Manifest != nil {
		if err := c.Manifest.Validate(); err != nil {
			return fmt.Errorf("manifest validation failed: %w", err)
		}
	}

	return nil
}

// IsRunning returns true if the component is currently running.
func (c *Component) IsRunning() bool {
	return c.Status == ComponentStatusRunning
}

// IsStopped returns true if the component is stopped.
func (c *Component) IsStopped() bool {
	return c.Status == ComponentStatusStopped
}

// IsAvailable returns true if the component is available for use.
func (c *Component) IsAvailable() bool {
	return c.Status == ComponentStatusAvailable
}

// HasError returns true if the component is in an error state.
func (c *Component) HasError() bool {
	return c.Status == ComponentStatusError
}

// IsRemote returns true if the component is a remote service.
func (c *Component) IsRemote() bool {
	return c.Source == ComponentSourceRemote
}

// IsExternal returns true if the component is an external binary.
func (c *Component) IsExternal() bool {
	return c.Source == ComponentSourceExternal
}

// IsInternal returns true if the component is built-in.
func (c *Component) IsInternal() bool {
	return c.Source == ComponentSourceInternal
}

// UpdateStatus updates the component status and sets the updated_at timestamp.
// If transitioning to running, sets started_at. If transitioning to stopped, sets stopped_at.
func (c *Component) UpdateStatus(status ComponentStatus) {
	oldStatus := c.Status
	c.Status = status
	c.UpdatedAt = time.Now()

	// Set started_at when transitioning to running
	if status == ComponentStatusRunning && oldStatus != ComponentStatusRunning {
		now := time.Now()
		c.StartedAt = &now
		c.StoppedAt = nil
	}

	// Set stopped_at when transitioning to stopped
	if status == ComponentStatusStopped && oldStatus == ComponentStatusRunning {
		now := time.Now()
		c.StoppedAt = &now
	}
}
