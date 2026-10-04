// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/otel/attribute"
)

// Verify core attributes are present

// Verify all attributes including runtime info

// Port should not be present

// Create a test span exporter

// Create and start a span

// Add component attributes

// Get the recorded span

// Verify attributes were added

// Should not panic

// Should not panic

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
