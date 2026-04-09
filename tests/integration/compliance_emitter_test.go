//go:build integration
// +build integration

// Package integration contains the audit-compliance-emitter end-to-end
// integration tests for the pinned queries from docs/AUDIT-FEATURE.md Q7.
//
// These tests require a live Neo4j + Redis. Run with:
//
//	go test -tags=integration ./tests/integration/...
//
// When the integration build tag is not set, this file compiles to
// nothing and the tests are skipped entirely.
package integration

import (
	"context"
	"testing"
	"time"
)

// TestCompliancePinnedQuery_Q1_GitlabAgentAt3AM reproduces pinned query 1
// from docs/AUDIT-FEATURE.md: "what did the gitlab agent write last night,
// and on whose behalf, and was it allowed by which policy". This test:
//
//  1. Stands up an in-process daemon with a live Neo4j + Redis.
//  2. Runs a synthetic gitlab agent through the harness, making writes
//     against the graph.
//  3. Executes the documented Cypher query.
//  4. Asserts the returned signals match the expected shape.
//
// The Cypher query under test is:
//
//	MATCH (cs:compliance_signal)
//	WHERE cs.caller_component = 'agent:gitlab-agent'
//	  AND cs.effect IN ['write', 'both']
//	  AND cs.occurred_at >= datetime('...')
//	RETURN cs ORDER BY cs.occurred_at
func TestCompliancePinnedQuery_Q1_GitlabAgentAt3AM(t *testing.T) {
	t.Skip("TODO: wire up in-process Neo4j + daemon fixture; see docs/AUDIT-FEATURE.md Q7")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_ = ctx
}

// TestCompliancePinnedQuery_Q2_URLTouch reproduces pinned query 2 from
// docs/AUDIT-FEATURE.md: "show me every signal that touched URL X in the
// last 24 hours, regardless of which agent or tool did it".
//
// The Cypher query under test is:
//
//	MATCH (cs:compliance_signal)
//	WHERE cs.resource_uri = $url
//	  AND cs.occurred_at >= datetime('...')
//	RETURN cs ORDER BY cs.occurred_at
func TestCompliancePinnedQuery_Q2_URLTouch(t *testing.T) {
	t.Skip("TODO: wire up in-process Neo4j + daemon fixture; see docs/AUDIT-FEATURE.md Q7")
}
