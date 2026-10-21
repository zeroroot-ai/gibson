// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkcg "github.com/zeroroot-ai/sdk/capabilitygrant"
)

// fakeRunAuthorizer records the run it is asked about and answers as told.
type fakeRunAuthorizer struct {
	calls   []string
	tenants []string
	allowed bool
	reason  string
	err     error
}

func (f *fakeRunAuthorizer) AuthorizeRun(_ context.Context, ownerTenant, runID, action, resource string) (allowed bool, reason string, err error) {
	f.calls = append(f.calls, runID+"|"+action+"|"+resource)
	f.tenants = append(f.tenants, ownerTenant)
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

	entry := sourceRunEntry(ctxForTenant(victimTenant), env.svc, victimTenant, callerWork)
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

	assert.Empty(t, sourceRunEntry(ctxForTenant(attackerTenant), env.svc, attackerTenant, foreign))
	assert.Empty(t, sourceRunEntry(ctxForTenant(victimTenant), env.svc, victimTenant, "no-such-work"))
	assert.Empty(t, sourceRunEntry(ctxForTenant(victimTenant), env.svc, victimTenant, ""))

	noRun := env.enqueueRun(t, victimTenant, "work-norun", "")
	assert.Empty(t, sourceRunEntry(ctxForTenant(victimTenant), env.svc, victimTenant, noRun))
}

// TestAuthorize_ASharedComponentIsDecidedForTheOwnerTenant proves that the run is
// decided for the tenant that owns the work item, not for the tenant of the
// caller. A shared component holds the system tenant and serves many tenants.
func TestAuthorize_ASharedComponentIsDecidedForTheOwnerTenant(t *testing.T) {
	env := newWorkIDEnv(t)
	fake := &fakeRunAuthorizer{allowed: true, reason: "fga_allow"}
	env.svc.WithRunAuthorizer(fake)
	workID := env.enqueueRun(t, victimTenant, "work-shared", "run-42")

	resp, err := env.svc.Authorize(auth.ContextWithTenant(context.Background(), auth.SystemTenant), &componentpb.AuthorizeRequest{
		WorkId: workID, Action: "execute", Resource: "tool:nmap",
	})

	require.NoError(t, err)
	assert.True(t, resp.GetAllowed())
	assert.Equal(t, []string{victimTenant}, fake.tenants, "the owner tenant of the work item decides, not the system tenant")
}

// TestDelegateToAgent_TheDelegatedAgentGetsTheRunOfItsCaller runs the real
// DelegateToAgent over a real queue and a real work-context registry. The agent
// that claims the delegated item carries the run of its caller, the run is bound
// to the delegated work id, and its own Authorize resolves to that run.
func TestDelegateToAgent_TheDelegatedAgentGetsTheRunOfItsCaller(t *testing.T) {
	env := newWorkIDEnv(t)
	fake := &fakeRunAuthorizer{allowed: true, reason: "fga_allow"}
	env.svc.WithRunAuthorizer(fake)
	const tenant = "test-tenant"
	source := env.enqueueRun(t, tenant, "work-source", "run-42")
	// PollWork records the mission of the source work item (gibson#1209).
	require.NoError(t, NewRedisWorkContextRegistry(env.state).
		RegisterWorkContext(context.Background(), source, "mission-7", tenant))

	item := env.delegateAndClaimAs(grantedCtx(componentCtx("agent_principal:acct-1"), "mission-7", "run-42"), t, tenant, source)
	assert.Contains(t, item.Context[authz.AuthzContextWorkKey], "run-42")
	// The delegated item carries the mission of its caller.
	assert.Equal(t, "mission-7", item.Context["mission_id"])
	// The request carries the run too, so the agent sends it on its callbacks.
	execReq := &agentpb.ExecuteRequest{}
	require.NoError(t, protojson.Unmarshal(item.Payload, execReq))
	assert.Equal(t, "run-42", execReq.GetMissionRunId())

	run, err := NewRedisWorkContextRegistry(env.state).WorkRun(context.Background(), item.WorkID)
	require.NoError(t, err)
	assert.Equal(t, "run-42", run)

	resp, err := env.svc.Authorize(ctxForTenant(tenant), &componentpb.AuthorizeRequest{
		WorkId: item.WorkID, Action: "execute", Resource: "tool:nmap",
	})
	require.NoError(t, err)
	assert.True(t, resp.GetAllowed())
	assert.Equal(t, []string{"run-42|execute|tool:nmap"}, fake.calls)
}

// A delegation from a work item is refused when its mission cannot be proved:
// a lookup that fails, a work item with no mission, a daemon with no resolver, a
// work item with no run, and a grant with no run (gibson#1235).
func TestDelegateToAgent_ARefusalWhenTheMissionOrTheRunCannotBeProved(t *testing.T) {
	const tenant = "test-tenant"
	taskJSON, err := json.Marshal(agent.Task{Goal: "recon"})
	require.NoError(t, err)

	newEnv := func(t *testing.T) *workIDEnv {
		env := newWorkIDEnv(t)
		env.svc.WithCapabilityChecker(grantedChecker())
		env.svc.WithGrantVerifier(fakeGrants{})
		env.svc.registry = &dispatchRegistry{info: ComponentInfo{Kind: "agent", Name: "recon-agent", InstanceID: "inst-agent"}}
		return env
	}
	call := func(env *workIDEnv, ctx context.Context, work string) error {
		_, callErr := env.svc.DelegateToAgent(ctx, &componentpb.DelegateToAgentRequest{
			WorkId: work, AgentName: "recon-agent", TaskJson: taskJSON,
		})
		return callErr
	}
	caller := componentCtx("agent_principal:acct-1")

	t.Run("a lookup that fails", func(t *testing.T) {
		env := newEnv(t)
		source := env.enqueueRun(t, tenant, "work-source", "run-42")
		require.NoError(t, NewRedisWorkContextRegistry(env.state).
			RegisterWorkContext(context.Background(), source, "mission-7", tenant))
		cfg := state.DefaultConfig()
		cfg.URL = "redis://" + env.mr.Addr()
		closed, stateErr := state.NewStateClient(cfg)
		require.NoError(t, stateErr)
		require.NoError(t, closed.Close())
		env.svc.WithMissionContextResolver(NewMissionContextResolver(closed, testLogger()))
		assert.Equal(t, codes.PermissionDenied, status.Code(call(env, grantedCtx(caller, "mission-7", "run-42"), source)))
	})

	t.Run("a work item with no mission", func(t *testing.T) {
		env := newEnv(t)
		source := env.enqueueRun(t, tenant, "work-source", "run-42")
		assert.Equal(t, codes.PermissionDenied, status.Code(call(env, grantedCtx(caller, "mission-7", "run-42"), source)))
	})

	t.Run("a daemon with no mission resolver", func(t *testing.T) {
		env := newEnv(t)
		env.svc.missionCtx = nil
		source := env.enqueueRun(t, tenant, "work-source", "run-42")
		assert.Equal(t, codes.PermissionDenied, status.Code(call(env, grantedCtx(caller, "mission-7", "run-42"), source)))
	})

	t.Run("a grant with no run", func(t *testing.T) {
		env := newEnv(t)
		source := env.enqueueRun(t, tenant, "work-source", "run-42")
		require.NoError(t, NewRedisWorkContextRegistry(env.state).
			RegisterWorkContext(context.Background(), source, "mission-7", tenant))
		assert.Equal(t, codes.PermissionDenied, status.Code(call(env, grantedCtx(caller, "mission-7", ""), source)))
	})

	t.Run("a work item of another run than the grant", func(t *testing.T) {
		env := newEnv(t)
		source := env.enqueueRun(t, tenant, "work-source", "run-42")
		require.NoError(t, NewRedisWorkContextRegistry(env.state).
			RegisterWorkContext(context.Background(), source, "mission-7", tenant))
		assert.Equal(t, codes.PermissionDenied, status.Code(call(env, grantedCtx(caller, "mission-7", "run-99"), source)))
	})

	t.Run("a work item with no run", func(t *testing.T) {
		env := newEnv(t)
		source := env.enqueueRun(t, tenant, "work-source", "")
		require.NoError(t, NewRedisWorkContextRegistry(env.state).
			RegisterWorkContext(context.Background(), source, "mission-7", tenant))
		assert.Equal(t, codes.PermissionDenied, status.Code(call(env, grantedCtx(caller, "mission-7", "run-42"), source)))
	})
}

// sourceRunEntry is the authz context entry that the run of a source work item
// gives, with the tenant check on the owner of the work item.
func sourceRunEntry(ctx context.Context, svc *ComponentServiceServer, tenant, work string) map[string]string {
	return authzContextEntry(svc.sourceWorkRun(ctx, tenant, work))
}

// fakeGrants stands for the daemon verifier. It accepts a token that names a
// tenant and a mission in its payload, and refuses a token whose signature
// segment is "foreign" (a token that a component signed itself).
type fakeGrants struct{}

func (fakeGrants) Verify(_ context.Context, token string) (sdkcg.Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == base64.RawURLEncoding.EncodeToString([]byte("foreign")) {
		return sdkcg.Claims{}, sdkcg.ErrUnknownKey
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]string
	if err := json.Unmarshal(raw, &payload); err != nil {
		return sdkcg.Claims{}, sdkcg.ErrClaimsInvalid
	}
	tenant, err := auth.NewTenantID("test-tenant")
	if err != nil {
		return sdkcg.Claims{}, fmt.Errorf("tenant: %w", err)
	}
	return sdkcg.Claims{Subject: "component:agent:caller", Tenant: tenant, MissionID: payload["mission_id"], MissionRunID: payload["mrid"], TaskID: "t"}, nil
}

// grantToken builds a grant token with a typ, a mission, a run and a signature.
func grantToken(typ, mission, run, signature string) string {
	enc := base64.RawURLEncoding.EncodeToString
	claims, _ := json.Marshal(map[string]string{"mission_id": mission, "mrid": run})
	return enc([]byte(`{"alg":"EdDSA","typ":"`+typ+`"}`)) + "." + enc(claims) + "." + enc([]byte(signature))
}

// grantedCtx presents a task grant that names a mission and a run.
func grantedCtx(ctx context.Context, mission, run string) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.Pairs("x-capability-grant", grantToken("JWT", mission, run, "sig")))
}

// delegateAndClaim delegates to "recon-agent" from the source work item with
// the real DelegateToAgent, and returns the delegated work item that the agent
// claims from the real queue.
func (e *workIDEnv) delegateAndClaim(t *testing.T, tenant, source string) *WorkItem {
	t.Helper()
	return e.delegateAndClaimAs(componentCtx("agent_principal:acct-1"), t, tenant, source)
}

// delegateAndClaimAs is delegateAndClaim with the context of the caller.
func (e *workIDEnv) delegateAndClaimAs(callerCtx context.Context, t *testing.T, tenant, source string) *WorkItem {
	t.Helper()
	e.svc.WithCapabilityChecker(grantedChecker())
	e.svc.WithGrantVerifier(fakeGrants{})
	e.svc.registry = &dispatchRegistry{info: ComponentInfo{Kind: "agent", Name: "recon-agent", InstanceID: "inst-agent"}}

	type claimed struct {
		item *WorkItem
		err  error
	}
	got := make(chan claimed, 1)
	go func() {
		ctx := context.Background()
		for range 100 {
			item, err := e.queue.Claim(ctx, tenant, "agent", "recon-agent", "inst-agent", 200*time.Millisecond)
			if err != nil || item != nil {
				if item != nil {
					res := agentpb.ExecuteResponse{Result: &typespb.Result{Status: typespb.ResultStatus_RESULT_STATUS_SUCCESS}}
					b, _ := protojson.Marshal(&res)
					err = e.queue.DeliverResult(ctx, item.WorkID, WorkResult{WorkID: item.WorkID, Result: b})
				}
				got <- claimed{item: item, err: err}
				return
			}
		}
		got <- claimed{err: errors.New("no work item was claimed")}
	}()

	taskJSON, err := json.Marshal(agent.Task{Goal: "recon"})
	require.NoError(t, err)
	_, err = e.svc.DelegateToAgent(callerCtx, &componentpb.DelegateToAgentRequest{
		WorkId: source, AgentName: "recon-agent", TaskJson: taskJSON,
	})
	require.NoError(t, err)

	c := <-got
	require.NoError(t, c.err)
	require.NotNil(t, c.item)
	return c.item
}

func TestDelegatedAuthzContext_WithoutARegistryTheAgentGetsNoRun(t *testing.T) {
	svc := newParityServer()
	assert.Empty(t, sourceRunEntry(context.Background(), svc, "test-tenant", "work-1"))
}

// brokenRedisEnv returns a work-context registry and queue over a Redis that is
// already closed, so every command fails.
func brokenRedisEnv(t *testing.T) (*RedisWorkContextRegistry, redis.UniversalClient) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })
	mr.Close()
	return NewRedisWorkContextRegistry(sc), client
}

func TestWorkRun_ARedisErrorIsNotAnUnknownRun(t *testing.T) {
	reg, client := brokenRedisEnv(t)

	_, err := reg.WorkRun(context.Background(), "work-1")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrWorkRunUnknown, "a broken Redis is not 'no run'; the caller must not read it as a missing run")

	err = bindWorkRun(context.Background(), client, WorkItem{
		WorkID: "work-1", Context: map[string]string{authz.AuthzContextWorkKey: `{"run_id":"run-1"}`},
	})
	require.Error(t, err, "a run that cannot be written fails the enqueue")
}

func TestBindWorkRun_AnAuthzContextWithNoRunBindsNothing(t *testing.T) {
	env := newWorkIDEnv(t)
	client := redis.NewClient(&redis.Options{Addr: env.mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	err := bindWorkRun(context.Background(), client, WorkItem{
		WorkID: "work-x", Context: map[string]string{authz.AuthzContextWorkKey: `{"issued_at":1}`},
	})
	require.NoError(t, err)
	_, err = NewRedisWorkContextRegistry(env.state).WorkRun(context.Background(), "work-x")
	require.ErrorIs(t, err, ErrWorkRunUnknown)
}

// A delegation from a work item is bound to the mission and the run of the
// verified task grant of the caller (gibson#1235).
func TestDelegateToAgent_TheWorkItemIsBoundToTheVerifiedGrantOfTheCaller(t *testing.T) {
	env := newWorkIDEnv(t)
	env.svc.WithCapabilityChecker(grantedChecker())
	env.svc.WithGrantVerifier(fakeGrants{})
	env.svc.registry = &dispatchRegistry{info: ComponentInfo{Kind: "agent", Name: "recon-agent", InstanceID: "inst-agent"}}
	const tenant = "test-tenant"
	foreign := env.enqueueRun(t, tenant, "work-foreign", "run-99")
	require.NoError(t, NewRedisWorkContextRegistry(env.state).
		RegisterWorkContext(context.Background(), foreign, "mission-other", tenant))

	taskJSON, err := json.Marshal(agent.Task{Goal: "recon"})
	require.NoError(t, err)
	req := &componentpb.DelegateToAgentRequest{WorkId: foreign, AgentName: "recon-agent", TaskJson: taskJSON}
	caller := componentCtx("agent_principal:acct-1")
	with := func(values ...string) context.Context {
		return metadata.NewIncomingContext(caller, metadata.Pairs("x-capability-grant", values[0]))
	}

	cases := map[string]context.Context{
		"a grant of another mission":              grantedCtx(caller, "mission-7", "run-7"),
		"a grant of the mission, but another run": grantedCtx(caller, "mission-other", "run-7"),
		"a token that a component signed itself":  with(grantToken("agent+jwt", "mission-other", "run-99", "sig")),
		"a task grant with a foreign signature":   with(grantToken("JWT", "mission-other", "run-99", "foreign")),
		"two grant headers": metadata.NewIncomingContext(caller, metadata.Pairs(
			"x-capability-grant", grantToken("JWT", "mission-other", "run-99", "sig"),
			"x-capability-grant", grantToken("JWT", "mission-other", "run-99", "sig"))),
		"no grant with a work item": caller,
	}
	for name, ctx := range cases {
		_, err := env.svc.DelegateToAgent(ctx, req)
		assert.Equal(t, codes.PermissionDenied, status.Code(err), name)
	}
}
