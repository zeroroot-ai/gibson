// Package plugin is a stub for analysistest fixtures used by the
// pluginlegacy analyzer test. This models both the new production plugin
// package (Serve, Descriptor) and the deleted pre-release symbols that the
// analyzer should flag (New, NewConfig, Initialize, Query, Shutdown, etc.).
// All symbols are exported so fixtures type-check correctly.
package plugin

import "context"

// Descriptor is the new minimal plugin descriptor type (Phase 2+).
type Descriptor struct {
	Name    string
	Version string
}

// Serve is the production plugin SDK entry point (Phase 8).
// Using this symbol should NOT be flagged by the pluginlegacy analyzer.
func Serve(ctx context.Context) error {
	return nil
}

// The following symbols are present in the stub so that violation fixtures
// compile correctly for analysistest. In production the real sdk/plugin
// package does NOT export these — they were deleted in Phase 1.
// The pluginlegacy analyzer flags any reference to them.

// New is a stub for the deleted plugin.New() builder.
func New(_ *Config) (any, error) { return nil, nil }

// NewConfig is a stub for the deleted plugin.NewConfig() builder.
func NewConfig() *Config { return &Config{} }

// ToDescriptor is a stub for the deleted plugin.ToDescriptor() helper.
func ToDescriptor(_ any) Descriptor { return Descriptor{} }

// Initialize is a stub for the deleted Plugin.Initialize method selector.
var Initialize = func(ctx context.Context, config map[string]any) error { return nil }

// Query is a stub for the deleted Plugin.Query method selector.
var Query = func(ctx context.Context, method string, params map[string]any) (any, error) {
	return nil, nil
}

// Shutdown is a stub for the deleted Plugin.Shutdown method selector.
var Shutdown = func(ctx context.Context) error { return nil }

// Health is a stub for the deleted Plugin.Health method selector.
var Health = func(ctx context.Context) {}

// Methods is a stub for the deleted Plugin.Methods method selector.
var Methods = func() []MethodDescriptor { return nil }

// MethodDescriptor is a stub for the deleted MethodDescriptor type.
type MethodDescriptor struct {
	Name        string
	Description string
}

// Config is a stub for the deleted plugin.Config builder type.
type Config struct{}

// MethodHandler is a stub for the deleted MethodHandler type.
type MethodHandler func(ctx context.Context, params map[string]any) (any, error)
