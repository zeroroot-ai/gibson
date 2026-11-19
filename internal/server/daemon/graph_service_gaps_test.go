// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	graphpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graph/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// brokenDataPool is a data-plane pool that cannot give a connection. The other
// methods of the interface stay unset, so a test that reaches one fails loud.
type brokenDataPool struct {
	datapool.Pool
	err error
}

func (p brokenDataPool) For(context.Context, auth.TenantID) (*datapool.Conn, error) {
	return nil, p.err
}

func graphOnPool(p datapool.Pool) *graphServer {
	return &graphServer{poolGetter: func() datapool.Pool { return p }, logger: slog.New(slog.DiscardHandler)}
}

func graphCtx() context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: "u1", Tenant: auth.MustNewTenantID("acme")})
}

func TestGraphFindingStore_NeedsATenantAndAPool(t *testing.T) {
	_, _, err := graphOnPool(brokenDataPool{}).findingStore(context.Background())
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, _, err = graphOnPool(nil).findingStore(graphCtx())
	assert.Equal(t, codes.Unavailable, status.Code(err))

	tenant, store, err := graphOnPool(brokenDataPool{}).findingStore(graphCtx())
	require.NoError(t, err)
	assert.Equal(t, "acme", tenant.String())
	assert.NotNil(t, store)
}

func TestFindingStoreError_KeepsTheClassOfAPoolError(t *testing.T) {
	assert.Equal(t, codes.FailedPrecondition,
		status.Code(findingStoreError(&datapool.NotProvisionedError{Tenant: "acme", Reason: "no data plane"})))
	assert.Equal(t, codes.Unavailable, status.Code(findingStoreError(&datapool.EvictedError{Tenant: "acme"})))
	assert.Equal(t, codes.Internal, status.Code(findingStoreError(errors.New("syntax error"))))
}

func TestGraphFindingReads_APoolFailureKeepsItsClass(t *testing.T) {
	srv := graphOnPool(brokenDataPool{err: &datapool.EvictedError{Tenant: "acme"}})
	ctx := graphCtx()

	_, err := srv.GetFindingCounts(ctx, &graphpb.GetFindingCountsRequest{GroupBy: graphpb.FindingCountGroupBy_CATEGORY})
	assert.Equal(t, codes.Unavailable, status.Code(err), "counts by category")
	_, err = srv.GetFindingCounts(ctx, &graphpb.GetFindingCountsRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err), "counts by severity")

	_, err = srv.GetFindingTimeSeries(ctx, &graphpb.GetFindingTimeSeriesRequest{Days: 9999})
	assert.Equal(t, codes.Unavailable, status.Code(err), "time series")

	_, err = srv.GetFindings(ctx, &graphpb.GetFindingsRequest{
		SeverityFilter: "high", MissionId: "6c5c9f0f-9f9f-4d9f-8f9f-9f9f9f9f9f9f",
	})
	assert.Equal(t, codes.Unavailable, status.Code(err), "findings list")
}

// No finding has a mission id that is not a UUID, so the list is empty and no query runs.
func TestGetFindings_AMissionIdThatIsNotAUUIDGivesAnEmptyList(t *testing.T) {
	srv := graphOnPool(brokenDataPool{err: errors.New("the pool must not be used")})
	resp, err := srv.GetFindings(graphCtx(), &graphpb.GetFindingsRequest{MissionId: "not-a-uuid"})
	require.NoError(t, err)
	assert.Empty(t, resp.GetFindings())
}

func TestFindingProperties_ListsTheStringsAndTheVerifiedActors(t *testing.T) {
	f := finding.EnhancedFinding{
		Finding: agent.Finding{
			Metadata:    map[string]any{"cve": "CVE-1", "score": 9.8, "tags": []string{"x"}},
			SubmittedBy: "component:agent:scout",
			EnrolledBy:  "admin-1",
		},
		AgentName: "scout",
	}
	assert.Equal(t, map[string]string{
		"cve": "CVE-1", "agent_name": "scout", "submitted_by": "component:agent:scout", "enrolled_by": "admin-1",
	}, findingProperties(f))
	assert.Empty(t, findingProperties(finding.EnhancedFinding{}))
}
