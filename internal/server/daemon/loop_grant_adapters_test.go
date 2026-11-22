// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/loopgrantstore"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

type stubLoopStore struct {
	grant *loopgrantstore.Grant
	err   error
}

func (s stubLoopStore) Put(context.Context, string, loopgrantstore.Grant) (*loopgrantstore.Grant, error) {
	return nil, errors.New("not used")
}

func (s stubLoopStore) Get(_ context.Context, _, _ string) (*loopgrantstore.Grant, error) {
	return s.grant, s.err
}

func (s stubLoopStore) ListPage(context.Context, string, string, bool, int) ([]loopgrantstore.Grant, error) {
	return nil, errors.New("not used")
}

func (s stubLoopStore) Delete(context.Context, string, string) error { return errors.New("not used") }

func lazyOver(st stubLoopStore) *lazyLoopGrants {
	return &lazyLoopGrants{stores: func() (loopgrantstore.Store, error) { return st, nil }}
}

func TestLazyLoopGrants_MapsTheStoreToTheHarnessSource(t *testing.T) {
	ctx := context.Background()
	got, err := lazyOver(stubLoopStore{grant: &loopgrantstore.Grant{
		ID: "g1", AgentName: "intake-agent", ToolClasses: []string{"ticket"}, HarnessCalls: []string{"SubmitFinding"}, Grantor: "user:a",
	}}).LoopGrantFor(ctx, "t", "intake-agent")
	require.NoError(t, err)
	assert.Equal(t, &harness.LoopGrant{
		ID: "g1", AgentName: "intake-agent", ToolClasses: []string{"ticket"}, HarnessCalls: []string{"SubmitFinding"}, Grantor: "user:a",
	}, got)

	_, err = lazyOver(stubLoopStore{err: loopgrantstore.ErrNotFound}).LoopGrantFor(ctx, "t", "a")
	require.ErrorIs(t, err, harness.ErrNoLoopGrant)

	boom := errors.New("boom")
	_, err = lazyOver(stubLoopStore{err: boom}).LoopGrantFor(ctx, "t", "a")
	require.ErrorIs(t, err, boom)
	require.NotErrorIs(t, err, harness.ErrNoLoopGrant, "an outage is no empty grant")

	failing := &lazyLoopGrants{stores: func() (loopgrantstore.Store, error) { return nil, boom }}
	_, err = failing.LoopGrantFor(ctx, "t", "a")
	require.ErrorIs(t, err, boom)
}

func TestLazyLoopGrants_NoDataPoolIsUnavailable(t *testing.T) {
	_, err := (&lazyLoopGrants{daemon: &daemonImpl{}}).LoopGrantFor(context.Background(), "t", "a")
	require.Error(t, err)
	assert.NotErrorIs(t, err, harness.ErrNoLoopGrant)
}

// The base grant of a member holds the loop grant calls, and nothing more.
func TestDeriveMemberRPCs(t *testing.T) {
	ctx := context.Background()
	base := harness.MemberBaseGrantRPCs()

	got, err := deriveMemberRPCs(ctx, lazyOver(stubLoopStore{err: loopgrantstore.ErrNotFound}), "t", "a")
	require.NoError(t, err)
	assert.Equal(t, base, got, "no grant gives the base surface")

	got, err = deriveMemberRPCs(ctx, lazyOver(stubLoopStore{grant: &loopgrantstore.Grant{ToolClasses: []string{"ticket"}}}), "t", "a")
	require.NoError(t, err)
	assert.Contains(t, got, "/gibson.harness.v1.HarnessCallbackService/CallToolProto")
	assert.Len(t, got, len(base)+1)

	_, err = deriveMemberRPCs(ctx, lazyOver(stubLoopStore{err: errors.New("down")}), "t", "a")
	require.Error(t, err)
}

func TestMemberGrantRPCs_NoDataPoolGivesTheBaseSurface(t *testing.T) {
	got, err := (&daemonImpl{}).memberGrantRPCs(context.Background(), "t", "a")
	require.NoError(t, err)
	assert.Equal(t, harness.MemberBaseGrantRPCs(), got)
}

func TestMemberGrantRPCSource_ReadsTheAgentOfTheSubject(t *testing.T) {
	src := memberGrantRPCSource{daemon: &daemonImpl{}}
	tid, err := auth.NewTenantID("acme")
	require.NoError(t, err)
	got, err := src.MemberGrantRPCs(context.Background(), sdkcg.Claims{Subject: "component:agent:intake-agent", Tenant: tid})
	require.NoError(t, err)
	assert.Equal(t, harness.MemberBaseGrantRPCs(), got)

	for _, subject := range []string{"user:alice", "component:agent:", "component:tool:nmap", ""} {
		_, err := src.MemberGrantRPCs(context.Background(), sdkcg.Claims{Subject: subject, Tenant: tid})
		require.Error(t, err, subject)
	}
}

func TestRegisterLoopGrant_NeedsThePoolAndTheAuditLogger(t *testing.T) {
	err := (&daemonImpl{}).registerLoopGrant(context.Background(), grpc.NewServer(), nil, nil)
	require.Error(t, err)
}
