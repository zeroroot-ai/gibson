//go:build integration
// +build integration

// Integration test for the audit-metadata-riders spec. Reproduces the
// gitlab-agent worked example from docs/AUDIT-FEATURE.md §
// "Extensibility in practice".
package integration

import (
	"context"
	"testing"
)

// TestMetadataRiders_GitlabAgent_WorkedExample verifies that an agent
// calling compliance.WithCustom with three custom keys results in those
// keys appearing in the emitted signal's custom bag in Neo4j.
func TestMetadataRiders_GitlabAgent_WorkedExample(t *testing.T) {
	t.Skip("requires in-process daemon + minimal gitlab-agent stub — not yet available")
	ctx := context.Background()
	_ = ctx
}
