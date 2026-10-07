// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

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

// Logger is an interface for logging warnings during component loading.
// This allows the caller to provide their own logger implementation.
type Logger interface {
	Warnf(format string, args ...interface{})
}
