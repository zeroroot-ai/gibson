//go:build integration
// +build integration

// Substrate projection integration tests — verify that audit logger
// entries and auth audit events project into compliance_signal nodes per
// audit-compliance-emitter Requirement 9.
package integration

import (
	"context"
	"testing"
	"time"
)

// TestAuditLoggerProjection verifies that every audit log entry written
// to Redis Streams is also projected as a compliance_signal node in
// Neo4j. The Redis write is authoritative — projection failures must
// NOT affect it (Requirement 9.4).
func TestAuditLoggerProjection(t *testing.T) {
	t.Skip("TODO: integration test requires live Redis + Neo4j; see Requirement 9")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_ = ctx
}

// TestAuthAuditProjection verifies that every auth audit event (auth_success,
// auth_failure, authz_allow, authz_deny) is projected as a
// compliance_signal with action=authz_decision. Decision is derived from
// the event type.
func TestAuthAuditProjection(t *testing.T) {
	t.Skip("TODO: integration test requires live Neo4j; see Requirement 9")
}
