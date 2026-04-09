//go:build integration
// +build integration

// Integration tests for audit-finding-compliance-mappings — verifies
// that the UpdateFindingComplianceMappings curator path works end-to-end
// against a real daemon + auth interceptor + audit logger.
package integration

import (
	"context"
	"testing"
)

func TestFindingComplianceMappings_AppendMode(t *testing.T) {
	t.Skip("TODO: requires in-process daemon + Neo4j + miniredis")
	ctx := context.Background()
	_ = ctx
}

func TestFindingComplianceMappings_ReplaceMode(t *testing.T) {
	t.Skip("TODO: requires in-process daemon + Neo4j + miniredis")
}

func TestFindingComplianceMappings_CrossTenantRejected(t *testing.T) {
	t.Skip("TODO: requires in-process daemon + auth")
}

func TestFindingComplianceMappings_ViewerRoleDenied(t *testing.T) {
	t.Skip("TODO: requires in-process daemon + auth")
}

func TestFindingComplianceMappings_EndToEnd_ToolToCypherToSARIF(t *testing.T) {
	t.Skip("TODO: requires in-process daemon + Neo4j + sarif exporter")
}
