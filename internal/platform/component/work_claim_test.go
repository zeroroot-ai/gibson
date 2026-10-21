// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"
)

func TestWorkClaimRegistry_BindAndRead(t *testing.T) {
	env := newWorkIDEnv(t)
	reg := NewRedisWorkContextRegistry(env.state)
	ctx := context.Background()

	require.Error(t, reg.BindWorkClaim(ctx, "", "s"))
	require.Error(t, reg.BindWorkClaim(ctx, "w", ""))
	_, err := reg.WorkClaimant(ctx, "")
	require.ErrorIs(t, err, ErrWorkClaimUnknown)
	_, err = reg.WorkClaimant(ctx, "never-claimed")
	require.ErrorIs(t, err, ErrWorkClaimUnknown)

	require.NoError(t, reg.BindWorkClaim(ctx, "w1", "agent_principal:1"))
	got, err := reg.WorkClaimant(ctx, "w1")
	require.NoError(t, err)
	assert.Equal(t, "agent_principal:1", got)

	// An empty stored value reads as no claimant.
	require.NoError(t, reg.stateClient.Client().Set(ctx, workClaimKey("w-empty"), "", 0).Err())
	_, err = reg.WorkClaimant(ctx, "w-empty")
	require.ErrorIs(t, err, ErrWorkClaimUnknown)

	// A broken Redis is an error that is not "unknown".
	env.mr.Close()
	require.Error(t, reg.BindWorkClaim(ctx, "w2", "s"))
	_, err = reg.WorkClaimant(ctx, "w1")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrWorkClaimUnknown)
}

// bindWorkClaim does nothing for a registry that cannot record claims, and for
// a caller with no identity. A failed write does not stop the poll.
func TestBindWorkClaim_Branches(t *testing.T) {
	env := newWorkIDEnv(t)
	env.svc.bindWorkClaim(withSubject(ctxForTenant(victimTenant), "agent_principal:1"), "")
	env.svc.bindWorkClaim(ctxForTenant(victimTenant), "w-noid-ctx")

	noID := auth.ContextWithTenantString(context.Background(), victimTenant)
	env.svc.bindWorkClaim(noID, "w-no-identity")
	_, err := NewRedisWorkContextRegistry(env.state).WorkClaimant(context.Background(), "w-no-identity")
	require.ErrorIs(t, err, ErrWorkClaimUnknown, "a caller with no identity records no claim")

	env.svc.workContext = struct{ WorkContextRegistry }{ownEveryWorkItem{tenant: victimTenant}}
	env.svc.bindWorkClaim(withSubject(noID, "agent_principal:1"), "w-other-registry") // no panic, no record

	env.svc.workContext = NewRedisWorkContextRegistry(env.state)
	env.mr.Close()
	env.svc.bindWorkClaim(withSubject(noID, "agent_principal:1"), "w-redis-down") // logged, no panic
}

func TestResolveClaimedWork_Refusals(t *testing.T) {
	// A registry that cannot record claims refuses the request.
	svc := boundedComponentServer(nil)
	svc.workContext = struct{ WorkContextRegistry }{ownEveryWorkItem{tenant: "test-tenant"}}
	_, err := svc.resolveClaimedWork(submitterCtx("test-tenant", "agent_principal:1"), "test-tenant", "w")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	// A caller with no identity is refused.
	env := newWorkIDEnv(t)
	workID := env.enqueueFor(t, victimTenant, "work-claim-noid")
	_, err = env.svc.resolveClaimedWork(auth.ContextWithTenantString(context.Background(), victimTenant), victimTenant, workID)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// A lookup that fails is an internal error.
	svc2 := boundedComponentServer(nil)
	svc2.workContext = failingClaims{ownEveryWorkItem{tenant: "test-tenant"}}
	_, err = svc2.resolveClaimedWork(submitterCtx("test-tenant", "agent_principal:1"), "test-tenant", "w")
	assert.Equal(t, codes.Internal, status.Code(err), "%v", err)
}

// failingClaims is a claim registry whose lookup fails.
type failingClaims struct{ ownEveryWorkItem }

func (failingClaims) WorkClaimant(context.Context, string) (string, error) {
	return "", errors.New("redis down")
}

func (failingClaims) BindWorkClaim(context.Context, string, string) error { return nil }
