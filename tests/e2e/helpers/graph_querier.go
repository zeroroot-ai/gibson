//go:build e2e
// +build e2e

// Package helpers — graph_querier.go
//
// Queries the GraphRAG knowledge graph (Neo4j) via the daemon's IntelligenceService
// gRPC endpoint to verify the dual-write path (Redis store + Neo4j graph).
//
// Design: the IntelligenceService gRPC surface does not expose a raw Cypher
// query or a per-mission Finding-node count endpoint. Two complementary strategies
// are therefore used:
//
//  1. GetRecurringVulnerabilities (threshold=1) — proves Neo4j has at least one
//     Finding node written by the probe agent, verifying the GraphRAG bridge
//     write path is alive. This is a proxy assertion; it does not distinguish
//     per-mission findings.
//
//  2. ExportFindings admin RPC (filtered by mission_id) — when the admin RPC
//     becomes implemented (tracked under prod-unimplemented-apis), this will
//     provide exact per-mission assertion. For now it falls back gracefully.
//
// NFR Reliability: retries once on transient gRPC error (Neo4j mid-rebalance).
// Deadline: 5s default poll (per design risk mitigation).
//
// Requirements: R1.9, NFR Reliability.
package helpers

import (
	"context"
	"fmt"
	"testing"
	"time"

	intelligencepb "github.com/zeroroot-ai/sdk/api/gen/intelligence/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// GraphQuerierConfig holds the connection config for the IntelligenceService.
// Reads from env vars at setup time; safe to pass around (no secrets).
type GraphQuerierConfig struct {
	// GRPCEndpoint is the daemon's gRPC address (e.g., "localhost:50002").
	// Defaults to the Kind NodePort convention.
	GRPCEndpoint string
}

// DefaultGraphQuerierConfig returns the default config for the Kind cluster.
func DefaultGraphQuerierConfig() GraphQuerierConfig {
	return GraphQuerierConfig{
		GRPCEndpoint: "localhost:50002",
	}
}

// GraphQuerier wraps the IntelligenceService gRPC client for e2e assertions.
type GraphQuerier struct {
	cfg    GraphQuerierConfig
	client intelligencepb.IntelligenceServiceClient
	conn   *grpc.ClientConn
}

// NewGraphQuerier creates a GraphQuerier connected to the daemon's IntelligenceService.
// The caller must call Close() when done.
//
// Uses insecure credentials (Kind dev cluster — no mTLS in test env).
func NewGraphQuerier(ctx context.Context, cfg GraphQuerierConfig) (*GraphQuerier, error) {
	conn, err := grpc.NewClient(
		cfg.GRPCEndpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("graph_querier: NewGraphQuerier: dial %s: %w", cfg.GRPCEndpoint, err)
	}
	return &GraphQuerier{
		cfg:    cfg,
		client: intelligencepb.NewIntelligenceServiceClient(conn),
		conn:   conn,
	}, nil
}

// Close releases the underlying gRPC connection.
func (q *GraphQuerier) Close() error {
	if q.conn != nil {
		return q.conn.Close()
	}
	return nil
}

// CountFindingNodes queries the IntelligenceService for finding nodes associated
// with the given missionID.
//
// Implementation strategy:
//   - Calls GetRecurringVulnerabilities(threshold=1) to check that the Neo4j
//     Finding node count is non-zero (proves the GraphRAG bridge wrote at least
//     one node).
//   - Returns the total finding count across all missions as a proxy for
//     per-mission assertion (the IntelligenceService does not expose per-mission
//     node counts; ExportFindings admin RPC is tracked under prod-unimplemented-apis).
//
// NFR Reliability: retries once on transient gRPC Unavailable (Neo4j mid-rebalance).
//
// Requirements: R1.9.
func (q *GraphQuerier) CountFindingNodes(ctx context.Context, missionID string) (int, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			// Single retry with brief delay (NFR Reliability: retry once on transient error).
			retryTimer := time.NewTimer(1 * time.Second)
			select {
			case <-ctx.Done():
				retryTimer.Stop()
				return 0, ctx.Err()
			case <-retryTimer.C:
			}
		}

		resp, err := q.client.GetRecurringVulnerabilities(ctx, &intelligencepb.GetRecurringVulnerabilitiesRequest{
			Threshold: 1, // any finding counts
			Limit:     100,
		})
		if err != nil {
			// Check if it's a transient error worth retrying.
			if s, ok := status.FromError(err); ok {
				if s.Code() == codes.Unavailable || s.Code() == codes.DeadlineExceeded {
					lastErr = fmt.Errorf("graph_querier: CountFindingNodes: transient gRPC error (attempt %d/2): %w", attempt+1, err)
					continue
				}
				// Unimplemented means Neo4j/Intelligence not available — treat as 0 nodes.
				if s.Code() == codes.Unimplemented {
					return 0, fmt.Errorf(
						"graph_querier: CountFindingNodes: IntelligenceService returned Unimplemented — "+
							"Neo4j or IntelligenceService may not be running in this cluster. "+
							"Ensure `intelligence.enabled: true` and Neo4j is reachable. "+
							"Mission: %s", missionID,
					)
				}
			}
			lastErr = err
			continue
		}

		// The GetRecurringVulnerabilities response has a total_count field which
		// represents how many unique vulnerability types were found in Neo4j.
		// We sum the occurrence counts to get the total number of Finding nodes.
		total := 0
		for _, v := range resp.GetVulnerabilities() {
			total += int(v.GetOccurrenceCount())
		}
		return total, nil
	}

	return 0, fmt.Errorf("graph_querier: CountFindingNodes: all retries failed: %w", lastErr)
}

// MustHaveFindingForMission polls until at least one Finding node exists in
// Neo4j for the given missionID (proxy: at least one finding node in the graph).
//
// Polls with a 5s deadline (per design risk mitigation: Neo4j write is async).
// Retries once on transient error (NFR Reliability).
//
// On failure: reports via t.Errorf with the MISSION-B catalog hint (Candidate C).
//
// Requirements: R1.9, NFR Reliability.
func (q *GraphQuerier) MustHaveFindingForMission(t *testing.T, ctx context.Context, missionID string) {
	t.Helper()

	const pollDeadline = 5 * time.Second
	pollCtx, cancel := context.WithTimeout(ctx, pollDeadline)
	defer cancel()

	backoff := 500 * time.Millisecond
	var lastErr error
	var lastCount int

	for {
		count, err := q.CountFindingNodes(pollCtx, missionID)
		if err != nil {
			lastErr = err
		} else {
			lastCount = count
			if count > 0 {
				t.Logf(
					"graph_querier: PASS — %d finding node(s) present in Neo4j (proxy assertion for mission %s). "+
						"Note: IntelligenceService returns aggregate counts; per-mission Cypher assertion "+
						"(MATCH (f:Finding {mission_id: $id}) RETURN count(f)) requires ExportFindings admin RPC "+
						"(tracked under prod-unimplemented-apis).",
					count, missionID,
				)
				return
			}
		}

		// Check if deadline expired.
		select {
		case <-pollCtx.Done():
			if lastErr != nil {
				t.Errorf(
					"graph_querier: MustHaveFindingForMission: IntelligenceService error after %s polling: %v "+
						"MISSION-B catalog: Candidate C — SubmitFinding wrote to Redis but GraphRAG bridge "+
						"async store failed silently (finding appears in /api/findings but not Neo4j). "+
						"Check internal/graphrag's DiscoveryProcessor and StoreAsync call in internal/harness/. "+
						"Mission: %s",
					pollDeadline, lastErr, missionID,
				)
			} else {
				t.Errorf(
					"graph_querier: MustHaveFindingForMission: 0 finding nodes in Neo4j after %s (mission=%s, lastCount=%d). "+
						"MISSION-B catalog: Candidate C — GraphRAG bridge async write may have failed silently. "+
						"Verify: (1) neo4j is running in the cluster, (2) IntelligenceService is registered, "+
						"(3) DiscoveryProcessor processed the probe agent's SubmitFinding call. "+
						"Cypher hint: MATCH (f:Finding {mission_id: $id}) RETURN count(f)",
					pollDeadline, missionID, lastCount,
				)
			}
			return
		default:
		}

		// Wait before next poll.
		timer := time.NewTimer(backoff)
		select {
		case <-pollCtx.Done():
			timer.Stop()
			// Will report failure on next loop iteration.
			continue
		case <-timer.C:
		}
		backoff = minDuration(backoff*2, 2*time.Second)
	}
}

// MustHaveFindingForMissionFromClient constructs a GraphQuerier on demand and
// asserts finding presence. Convenience wrapper for tests that don't pre-build
// a GraphQuerier.
//
// Skips gracefully (t.Skip, not t.Fatal) if the IntelligenceService is
// unavailable (Neo4j not deployed in this cluster).
//
// Requirements: R1.9.
func MustHaveFindingForMissionFromClient(t *testing.T, ctx context.Context, missionID string) {
	t.Helper()

	cfg := DefaultGraphQuerierConfig()
	q, err := NewGraphQuerier(ctx, cfg)
	if err != nil {
		t.Skipf(
			"graph_querier: MustHaveFindingForMissionFromClient: could not connect to IntelligenceService at %s: %v — "+
				"skipping Neo4j dual-write assertion (Neo4j may not be deployed in this test cluster)",
			cfg.GRPCEndpoint, err,
		)
		return
	}
	defer func() {
		if closeErr := q.Close(); closeErr != nil {
			t.Logf("graph_querier: Close: %v", closeErr)
		}
	}()

	q.MustHaveFindingForMission(t, ctx, missionID)
}
