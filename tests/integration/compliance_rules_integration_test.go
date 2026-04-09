//go:build integration
// +build integration

// Integration test for audit-compliance-rules-catalog — emits a signal
// through a real harness call, verifies control_ids are stamped, and
// queries via ListComplianceEvidence RPC.
package integration

import (
	"context"
	"testing"
)

func TestComplianceRules_SOC2_CC7_1_EndToEnd(t *testing.T) {
	t.Skip("TODO: requires in-process daemon + Neo4j; see docs/sdk/compliance-rules-authoring.md")
	ctx := context.Background()
	_ = ctx
}
