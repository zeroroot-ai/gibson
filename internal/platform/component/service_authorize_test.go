// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeRunAuthorizer records the run it is asked about and answers as told.
type fakeRunAuthorizer struct {
	calls   []string
	allowed bool
	reason  string
	err     error
}

func (f *fakeRunAuthorizer) AuthorizeRun(_ context.Context, runID, action, resource string) (allowed bool, reason string, err error) {
	f.calls = append(f.calls, runID+"|"+action+"|"+resource)
	return f.allowed, f.reason, f.err
}

// enqueueRun dispatches a work item that carries the AuthzContext of runID, as
// the harness does, and returns its work id.
func (e *workIDEnv) enqueueRun(t *testing.T, tenant, workID, runID string) string {
	t.Helper()
	item := WorkItem{WorkID: workID, WorkType: "execute", Context: map[string]string{}}
	if runID != "" {
		ac, err := json.Marshal(map[string]any{"run_id": runID, "issued_at": 1, "ttl_seconds": 600})
		require.NoError(t, err)
		item.Context[authz.AuthzContextWorkKey] = string(ac)
	}
	_, err := e.queue.Enqueue(context.Background(), tenant, "tool", "nmap", item)
	require.NoError(t, err)
	return workID
}

func ctxForTenant(tenant string) context.Context {
	return auth.ContextWithTenantString(context.Background(), tenant)
}

func TestAuthorize_RunsTheDecisionOfTheCallbackPathOnTheRunOfTheWorkItem(t *testing.T) {
	env := newWorkIDEnv(t)
	fake := &fakeRunAuthorizer{allowed: true, reason: "fga_allow"}
	env.svc.WithRunAuthorizer(fake)
	workID := env.enqueueRun(t, victimTenant, "work-az-1", "run-42")

	resp, err := env.svc.Authorize(ctxForTenant(victimTenant), &componentpb.AuthorizeRequest{
		WorkId: workID, Action: "execute", Resource: "tool:nmap",
	})

	require.NoError(t, err)
	assert.True(t, resp.GetAllowed())
	assert.Equal(t, "fga_allow", resp.GetReason())
	assert.Equal(t, []string{"run-42|execute|tool:nmap"}, fake.calls, "the run comes from the work item")
}

func TestAuthorize_ADenialIsNotAnError(t *testing.T) {
	env := newWorkIDEnv(t)
	env.svc.WithRunAuthorizer(&fakeRunAuthorizer{allowed: false, reason: "not_authorized"})
	workID := env.enqueueRun(t, victimTenant, "work-az-2", "run-42")

	resp, err := env.svc.Authorize(ctxForTenant(victimTenant), &componentpb.AuthorizeRequest{
		WorkId: workID, Action: "execute", Resource: "tool:nmap",
	})

	require.NoError(t, err)
	assert.False(t, resp.GetAllowed())
	assert.Equal(t, "not_authorized", resp.GetReason())
}

func TestAuthorize_Refusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *workIDEnv) (*componentpb.AuthorizeRequest, string)
		want  codes.Code
	}{
		{"another tenant's work item", func(e *workIDEnv) (*componentpb.AuthorizeRequest, string) {
			id := e.enqueueRun(t, victimTenant, "w1", "run-1")
			return &componentpb.AuthorizeRequest{WorkId: id, Action: "execute", Resource: "tool:nmap"}, attackerTenant
		}, codes.PermissionDenied},
		{"an unknown work id", func(*workIDEnv) (*componentpb.AuthorizeRequest, string) {
			return &componentpb.AuthorizeRequest{WorkId: "nope", Action: "execute", Resource: "tool:nmap"}, victimTenant
		}, codes.PermissionDenied},
		{"a work item with no mission run", func(e *workIDEnv) (*componentpb.AuthorizeRequest, string) {
			id := e.enqueueRun(t, victimTenant, "w2", "")
			return &componentpb.AuthorizeRequest{WorkId: id, Action: "execute", Resource: "tool:nmap"}, victimTenant
		}, codes.FailedPrecondition},
		{"no work id", func(*workIDEnv) (*componentpb.AuthorizeRequest, string) {
			return &componentpb.AuthorizeRequest{Action: "execute", Resource: "tool:nmap"}, victimTenant
		}, codes.InvalidArgument},
		{"no action", func(e *workIDEnv) (*componentpb.AuthorizeRequest, string) {
			id := e.enqueueRun(t, victimTenant, "w3", "run-1")
			return &componentpb.AuthorizeRequest{WorkId: id, Resource: "tool:nmap"}, victimTenant
		}, codes.InvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newWorkIDEnv(t)
			fake := &fakeRunAuthorizer{allowed: true}
			env.svc.WithRunAuthorizer(fake)
			req, tenant := tc.setup(env)

			resp, err := env.svc.Authorize(ctxForTenant(tenant), req)

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, tc.want, status.Code(err))
			assert.Empty(t, fake.calls, "a refused request never reaches the decision")
		})
	}
}

func TestAuthorize_NoRunAuthorizerIsARefusalNotAnAllow(t *testing.T) {
	env := newWorkIDEnv(t)
	workID := env.enqueueRun(t, victimTenant, "work-az-3", "run-1")

	resp, err := env.svc.Authorize(ctxForTenant(victimTenant), &componentpb.AuthorizeRequest{
		WorkId: workID, Action: "execute", Resource: "tool:nmap",
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestAuthorize_TheDecisionErrorsPassThroughByCode(t *testing.T) {
	for _, code := range []codes.Code{codes.NotFound, codes.FailedPrecondition, codes.Unavailable} {
		t.Run(code.String(), func(t *testing.T) {
			env := newWorkIDEnv(t)
			env.svc.WithRunAuthorizer(&fakeRunAuthorizer{err: status.Error(code, "decision")})
			workID := env.enqueueRun(t, victimTenant, "work-az-4", "run-1")

			resp, err := env.svc.Authorize(ctxForTenant(victimTenant), &componentpb.AuthorizeRequest{
				WorkId: workID, Action: "execute", Resource: "tool:nmap",
			})

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, code, status.Code(err))
		})
	}
}

func TestWorkQueue_EnqueueBindsTheMissionRun(t *testing.T) {
	env := newWorkIDEnv(t)
	env.enqueueRun(t, victimTenant, "work-run-1", "run-7")
	env.enqueueRun(t, victimTenant, "work-run-2", "")

	reg := NewRedisWorkContextRegistry(env.state)
	run, err := reg.WorkRun(context.Background(), "work-run-1")
	require.NoError(t, err)
	assert.Equal(t, "run-7", run)

	_, err = reg.WorkRun(context.Background(), "work-run-2")
	require.ErrorIs(t, err, ErrWorkRunUnknown)
	_, err = reg.WorkRun(context.Background(), "")
	require.ErrorIs(t, err, ErrWorkRunUnknown)
}

func TestWorkQueue_EnqueueRefusesABadAuthzContext(t *testing.T) {
	env := newWorkIDEnv(t)
	_, err := env.queue.Enqueue(context.Background(), victimTenant, "tool", "nmap", WorkItem{
		WorkID: "work-bad", WorkType: "execute",
		Context: map[string]string{authz.AuthzContextWorkKey: "{not json"},
	})
	require.Error(t, err, "a work item whose run cannot be read must not be dispatched")
}

// TestDelegatedAgentGetsTheRunOfItsCaller proves that the work item of a
// delegated agent carries the run of the caller, so its own Authorize resolves.
func TestDelegatedAgentGetsTheRunOfItsCaller(t *testing.T) {
	env := newWorkIDEnv(t)
	fake := &fakeRunAuthorizer{allowed: true, reason: "fga_allow"}
	env.svc.WithRunAuthorizer(fake)
	callerWork := env.enqueueRun(t, victimTenant, "work-caller", "run-42")

	entry := env.svc.delegatedAuthzContext(ctxForTenant(victimTenant), victimTenant, callerWork)
	require.Contains(t, entry, authz.AuthzContextWorkKey)

	// The delegated item goes through the same Enqueue as any other work item.
	_, err := env.queue.Enqueue(context.Background(), victimTenant, "agent", "recon", WorkItem{
		WorkID: "work-delegated", WorkType: WorkTypeAgentExecute, Context: entry,
	})
	require.NoError(t, err)

	resp, err := env.svc.Authorize(ctxForTenant(victimTenant), &componentpb.AuthorizeRequest{
		WorkId: "work-delegated", Action: "execute", Resource: "tool:nmap",
	})
	require.NoError(t, err)
	assert.True(t, resp.GetAllowed())
	assert.Equal(t, []string{"run-42|execute|tool:nmap"}, fake.calls, "the delegated agent acts for the run of its caller")
}

// TestDelegatedAgentCannotBorrowTheRunOfAnotherTenant proves that the source
// work id the caller names is checked against its owner before it selects a run.
func TestDelegatedAgentCannotBorrowTheRunOfAnotherTenant(t *testing.T) {
	env := newWorkIDEnv(t)
	foreign := env.enqueueRun(t, victimTenant, "work-foreign", "run-victim")

	assert.Empty(t, env.svc.delegatedAuthzContext(ctxForTenant(attackerTenant), attackerTenant, foreign))
	assert.Empty(t, env.svc.delegatedAuthzContext(ctxForTenant(victimTenant), victimTenant, "no-such-work"))
	assert.Empty(t, env.svc.delegatedAuthzContext(ctxForTenant(victimTenant), victimTenant, ""))

	noRun := env.enqueueRun(t, victimTenant, "work-norun", "")
	assert.Empty(t, env.svc.delegatedAuthzContext(ctxForTenant(victimTenant), victimTenant, noRun))
}
