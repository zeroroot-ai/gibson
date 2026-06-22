package component

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestComponentAttributes tests the ComponentAttributes function
func TestComponentAttributes(t *testing.T) {
	t.Run("nil component returns empty attributes", func(t *testing.T) {
		attrs := ComponentAttributes(nil)
		assert.Empty(t, attrs)
	})

	t.Run("minimal component attributes", func(t *testing.T) {
		comp := &Component{
			Kind:    ComponentKindAgent,
			Name:    "test-agent",
			Version: "1.0.0",
			Source:  ComponentSourceExternal,
			Status:  ComponentStatusAvailable,
		}

		attrs := ComponentAttributes(comp)

		// Verify core attributes are present
		assertHasAttribute(t, attrs, AttrComponentKind, "agent")
		assertHasAttribute(t, attrs, AttrComponentName, "test-agent")
		assertHasAttribute(t, attrs, AttrComponentVersion, "1.0.0")
		assertHasAttribute(t, attrs, AttrComponentSource, "external")
		assertHasAttribute(t, attrs, AttrComponentStatus, "available")
	})

	t.Run("running component with PID and port", func(t *testing.T) {
		now := time.Now()
		comp := &Component{
			Kind:      ComponentKindTool,
			Name:      "test-tool",
			Version:   "2.0.0",
			RepoPath:  "/path/to/tool",
			BinPath:   "/path/to/bin/tool",
			Source:    ComponentSourceExternal,
			Status:    ComponentStatusRunning,
			Port:      8080,
			PID:       12345,
			CreatedAt: now,
			UpdatedAt: now,
			StartedAt: &now,
		}

		attrs := ComponentAttributes(comp)

		// Verify all attributes including runtime info
		assertHasAttribute(t, attrs, AttrComponentKind, "tool")
		assertHasAttribute(t, attrs, AttrComponentName, "test-tool")
		assertHasAttribute(t, attrs, AttrComponentVersion, "2.0.0")
		assertHasAttribute(t, attrs, AttrComponentSource, "external")
		assertHasAttribute(t, attrs, AttrComponentStatus, "running")
		assertHasIntAttribute(t, attrs, AttrComponentPort, 8080)
		assertHasIntAttribute(t, attrs, AttrComponentPID, 12345)
		assertHasAttribute(t, attrs, "gibson.component.repo_path", "/path/to/tool")
		assertHasAttribute(t, attrs, "gibson.component.bin_path", "/path/to/bin/tool")
	})

	t.Run("component with manifest", func(t *testing.T) {
		manifest := &Manifest{
			Name:        "test-plugin",
			Version:     "1.0.0",
			Description: "Test plugin description",
			Author:      "Test Author",
			License:     "MIT",
			Runtime: &RuntimeConfig{
				Type:       RuntimeTypeGo,
				Entrypoint: "./plugin",
				HealthURL:  "/health",
			},
			Build: &BuildConfig{
				Command: "make build",
			},
		}

		comp := &Component{
			Kind:     ComponentKindPlugin,
			Name:     "test-plugin",
			Version:  "1.0.0",
			Source:   ComponentSourceExternal,
			Status:   ComponentStatusAvailable,
			Manifest: manifest,
		}

		attrs := ComponentAttributes(comp)

		// Verify manifest attributes are included
		assertHasAttribute(t, attrs, "gibson.component.description", "Test plugin description")
		assertHasAttribute(t, attrs, "gibson.component.author", "Test Author")
		assertHasAttribute(t, attrs, "gibson.component.license", "MIT")
		assertHasAttribute(t, attrs, "gibson.component.entrypoint", "./plugin")
		assertHasAttribute(t, attrs, "gibson.component.health_url", "/health")
		assertHasAttribute(t, attrs, AttrBuildCommand, "make build")
	})
}

// TestManifestAttributes tests the ManifestAttributes function
func TestManifestAttributes(t *testing.T) {
	t.Run("nil manifest returns empty attributes", func(t *testing.T) {
		attrs := ManifestAttributes(nil)
		assert.Empty(t, attrs)
	})

	t.Run("complete manifest attributes", func(t *testing.T) {
		manifest := &Manifest{
			Name:        "test-agent",
			Version:     "1.0.0",
			Description: "Test agent",
			Author:      "Test Author",
			License:     "Apache-2.0",
			Runtime: &RuntimeConfig{
				Type:       RuntimeTypeGo,
				Entrypoint: "./agent",
				HealthURL:  "/healthz",
			},
			Build: &BuildConfig{
				Command: "go build",
			},
		}

		attrs := ManifestAttributes(manifest)

		assertHasAttribute(t, attrs, "gibson.component.description", "Test agent")
		assertHasAttribute(t, attrs, "gibson.component.author", "Test Author")
		assertHasAttribute(t, attrs, "gibson.component.license", "Apache-2.0")
		assertHasAttribute(t, attrs, "gibson.component.entrypoint", "./agent")
		assertHasAttribute(t, attrs, "gibson.component.health_url", "/healthz")
		assertHasAttribute(t, attrs, AttrBuildCommand, "go build")
	})
}

// TestInstallResultAttributes tests the InstallResultAttributes function
func TestInstallResultAttributes(t *testing.T) {
	t.Run("nil result returns empty attributes", func(t *testing.T) {
		attrs := InstallResultAttributes(nil)
		assert.Empty(t, attrs)
	})

	t.Run("install result with build output", func(t *testing.T) {
		result := &InstallResult{
			Path:        "/path/to/component",
			Duration:    5 * time.Second,
			BuildOutput: "Build successful\n",
			Installed:   true,
			Updated:     false,
		}

		attrs := InstallResultAttributes(result)

		assertHasBoolAttribute(t, attrs, "gibson.component.installed", true)
		assertHasBoolAttribute(t, attrs, "gibson.component.updated", false)
		assertHasAttribute(t, attrs, "gibson.component.install_path", "/path/to/component")
		assertHasBoolAttribute(t, attrs, "gibson.component.has_build_output", true)
	})
}

// TestUpdateResultAttributes tests the UpdateResultAttributes function
func TestUpdateResultAttributes(t *testing.T) {
	t.Run("nil result returns empty attributes", func(t *testing.T) {
		attrs := UpdateResultAttributes(nil)
		assert.Empty(t, attrs)
	})

	t.Run("update result with version change", func(t *testing.T) {
		result := &UpdateResult{
			Path:       "/path/to/component",
			Duration:   3 * time.Second,
			Updated:    true,
			Restarted:  false,
			OldVersion: "1.0.0",
			NewVersion: "1.1.0",
		}

		attrs := UpdateResultAttributes(result)

		assertHasBoolAttribute(t, attrs, "gibson.component.updated", true)
		assertHasBoolAttribute(t, attrs, "gibson.component.restarted", false)
		assertHasAttribute(t, attrs, "gibson.component.old_version", "1.0.0")
		assertHasAttribute(t, attrs, "gibson.component.new_version", "1.1.0")
	})
}

// TestUninstallResultAttributes tests the UninstallResultAttributes function
func TestUninstallResultAttributes(t *testing.T) {
	t.Run("nil result returns empty attributes", func(t *testing.T) {
		attrs := UninstallResultAttributes(nil)
		assert.Empty(t, attrs)
	})

	t.Run("uninstall result from running component", func(t *testing.T) {
		result := &UninstallResult{
			Name:       "test-component",
			Kind:       ComponentKindAgent,
			Path:       "/path/to/component",
			Duration:   2 * time.Second,
			WasRunning: true,
			WasStopped: true,
		}

		attrs := UninstallResultAttributes(result)

		assertHasAttribute(t, attrs, AttrComponentName, "test-component")
		assertHasAttribute(t, attrs, AttrComponentKind, "agent")
		assertHasBoolAttribute(t, attrs, "gibson.component.was_running", true)
		assertHasBoolAttribute(t, attrs, "gibson.component.was_stopped", true)
	})
}

// TestLifecycleAttributes tests the LifecycleAttributes function
func TestLifecycleAttributes(t *testing.T) {
	t.Run("lifecycle attributes with port", func(t *testing.T) {
		attrs := LifecycleAttributes("start", 8080, 1500)

		assertHasAttribute(t, attrs, "gibson.component.operation", "start")
		assertHasIntAttribute(t, attrs, AttrComponentPort, 8080)
		assertHasInt64Attribute(t, attrs, "gibson.component.operation_duration_ms", 1500)
	})

	t.Run("lifecycle attributes without port", func(t *testing.T) {
		attrs := LifecycleAttributes("stop", 0, 500)

		assertHasAttribute(t, attrs, "gibson.component.operation", "stop")
		assertHasInt64Attribute(t, attrs, "gibson.component.operation_duration_ms", 500)
		// Port should not be present
		for _, attr := range attrs {
			assert.NotEqual(t, AttrComponentPort, string(attr.Key))
		}
	})
}

// TestErrorAttributes tests the ErrorAttributes function
func TestErrorAttributes(t *testing.T) {
	t.Run("nil error returns empty attributes", func(t *testing.T) {
		attrs := ErrorAttributes(nil, "test_operation")
		assert.Empty(t, attrs)
	})

	t.Run("standard error attributes", func(t *testing.T) {
		err := assert.AnError
		attrs := ErrorAttributes(err, "install")

		assertHasBoolAttribute(t, attrs, "error", true)
		assertHasAttribute(t, attrs, "error.message", err.Error())
		assertHasAttribute(t, attrs, "gibson.component.failed_operation", "install")
	})

	t.Run("component error attributes", func(t *testing.T) {
		compErr := NewComponentNotFoundError("test-component").
			WithContext("path", "/test/path")

		attrs := ErrorAttributes(compErr, "uninstall")

		assertHasBoolAttribute(t, attrs, "error", true)
		assertHasAttribute(t, attrs, "error.code", string(ErrCodeComponentNotFound))
		assertHasAttribute(t, attrs, "error.type", "ComponentError")
		assertHasAttribute(t, attrs, AttrComponentName, "test-component")
	})
}

// TestAddComponentAttributes tests the AddComponentAttributes function
func TestAddComponentAttributes(t *testing.T) {
	t.Run("adds attributes to span", func(t *testing.T) {
		// Create a test span exporter
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithSyncer(exporter),
		)
		tracer := tp.Tracer("test")

		// Create and start a span
		_, span := tracer.Start(t.Context(), "test-span")

		comp := &Component{
			Kind:    ComponentKindAgent,
			Name:    "test-agent",
			Version: "1.0.0",
			Source:  ComponentSourceExternal,
			Status:  ComponentStatusAvailable,
		}

		// Add component attributes
		AddComponentAttributes(span, comp)
		span.End()

		// Get the recorded span
		spans := exporter.GetSpans()
		require.Len(t, spans, 1)

		spanData := spans[0]
		attrs := spanData.Attributes

		// Verify attributes were added
		assertHasAttributeInSlice(t, attrs, AttrComponentKind, "agent")
		assertHasAttributeInSlice(t, attrs, AttrComponentName, "test-agent")
		assertHasAttributeInSlice(t, attrs, AttrComponentVersion, "1.0.0")
	})

	t.Run("handles nil span gracefully", func(t *testing.T) {
		comp := &Component{
			Kind:    ComponentKindAgent,
			Name:    "test-agent",
			Version: "1.0.0",
			Source:  ComponentSourceExternal,
			Status:  ComponentStatusAvailable,
		}

		// Should not panic
		assert.NotPanics(t, func() {
			AddComponentAttributes(nil, comp)
		})
	})

	t.Run("handles nil component gracefully", func(t *testing.T) {
		exporter := tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithSyncer(exporter),
		)
		tracer := tp.Tracer("test")

		_, span := tracer.Start(t.Context(), "test-span")

		// Should not panic
		assert.NotPanics(t, func() {
			AddComponentAttributes(span, nil)
		})

		span.End()
	})
}

// TestSpanNameConstants tests that span name constants are properly defined
func TestSpanNameConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"install span", SpanComponentInstall, "gibson.component.install"},
		{"build span", SpanComponentBuild, "gibson.component.build"},
		{"start span", SpanComponentStart, "gibson.component.start"},
		{"stop span", SpanComponentStop, "gibson.component.stop"},
		{"health span", SpanComponentHealth, "gibson.component.health"},
		{"uninstall span", SpanComponentUninstall, "gibson.component.uninstall"},
		{"update span", SpanComponentUpdate, "gibson.component.update"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

// TestAttributeKeyConstants tests that attribute key constants are properly defined
func TestAttributeKeyConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"component kind", AttrComponentKind, "gibson.component.kind"},
		{"component name", AttrComponentName, "gibson.component.name"},
		{"component version", AttrComponentVersion, "gibson.component.version"},
		{"component source", AttrComponentSource, "gibson.component.source"},
		{"component status", AttrComponentStatus, "gibson.component.status"},
		{"component port", AttrComponentPort, "gibson.component.port"},
		{"component PID", AttrComponentPID, "gibson.component.pid"},
		{"repo URL", AttrRepoURL, "gibson.component.repo_url"},
		{"build command", AttrBuildCommand, "gibson.component.build_command"},
		{"build duration", AttrBuildDuration, "gibson.component.build_duration_ms"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

// Helper functions for assertions

func assertHasAttribute(t *testing.T, attrs []attribute.KeyValue, key string, expectedValue string) {
	t.Helper()
	found := false
	for _, attr := range attrs {
		if string(attr.Key) == key {
			found = true
			assert.Equal(t, expectedValue, attr.Value.AsString(), "attribute %s has wrong value", key)
			break
		}
	}
	assert.True(t, found, "attribute %s not found", key)
}

func assertHasIntAttribute(t *testing.T, attrs []attribute.KeyValue, key string, expectedValue int) {
	t.Helper()
	found := false
	for _, attr := range attrs {
		if string(attr.Key) == key {
			found = true
			assert.Equal(t, int64(expectedValue), attr.Value.AsInt64(), "attribute %s has wrong value", key)
			break
		}
	}
	assert.True(t, found, "attribute %s not found", key)
}

func assertHasInt64Attribute(t *testing.T, attrs []attribute.KeyValue, key string, expectedValue int64) {
	t.Helper()
	found := false
	for _, attr := range attrs {
		if string(attr.Key) == key {
			found = true
			assert.Equal(t, expectedValue, attr.Value.AsInt64(), "attribute %s has wrong value", key)
			break
		}
	}
	assert.True(t, found, "attribute %s not found", key)
}

func assertHasBoolAttribute(t *testing.T, attrs []attribute.KeyValue, key string, expectedValue bool) {
	t.Helper()
	found := false
	for _, attr := range attrs {
		if string(attr.Key) == key {
			found = true
			assert.Equal(t, expectedValue, attr.Value.AsBool(), "attribute %s has wrong value", key)
			break
		}
	}
	assert.True(t, found, "attribute %s not found", key)
}

func assertHasAttributeInSlice(t *testing.T, attrs []attribute.KeyValue, key string, expectedValue string) {
	t.Helper()
	found := false
	for _, attr := range attrs {
		if string(attr.Key) == key {
			found = true
			assert.Equal(t, expectedValue, attr.Value.AsString(), "attribute %s has wrong value", key)
			break
		}
	}
	assert.True(t, found, "attribute %s not found", key)
}
