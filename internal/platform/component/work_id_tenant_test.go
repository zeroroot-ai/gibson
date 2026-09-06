// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// work_id_tenant_test.go covers the tenant binding on component-supplied work
// ids.
//
// A work id leaves the daemon on PollWork and comes back on SubmitResult and
// SubmitFinding — RPCs whose arguments the remote component chooses. These tests
// hold the line that the returning id must resolve to the tenant that enqueued
// it before it is allowed to select a result slot, a mission, or a graph scope.

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	victimTenant   = "tenant-victim"
	attackerTenant = "tenant-attacker"
)

// workIDEnv wires a ComponentServiceServer, a work queue and a work-context
// registry over one miniredis, so the queue's owner binding is the same binding
// the service reads. mr is exposed for raw key assertions: the point of several
// of these tests is which Redis key was written, which no fake can stand in for.
type workIDEnv struct {
	svc   *ComponentServiceServer
	queue WorkQueue
	state *state.StateClient
	mr    *miniredis.Miniredis
}

func newWorkIDEnv(t *testing.T) *workIDEnv {
	t.Helper()

	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })

	queue := NewRedisWorkQueue(client)
	svc := NewComponentServiceServer(&noopRegistry{}, queue, testLogger(), nil, nil, nil, nil).
		WithWorkContextRegistry(NewRedisWorkContextRegistry(sc))

	return &workIDEnv{svc: svc, queue: queue, state: sc, mr: mr}
}

// enqueueFor dispatches a work item on tenant's stream and returns its work id,
// which is what a component polling that stream would receive.
func (e *workIDEnv) enqueueFor(t *testing.T, tenant, workID string) string {
	t.Helper()

	_, err := e.queue.Enqueue(context.Background(), tenant, "tool", "nmap", WorkItem{
		WorkID:   workID,
		WorkType: "execute",
	})
	require.NoError(t, err)
	return workID
}

// ---------------------------------------------------------------------------
// SubmitResult
// ---------------------------------------------------------------------------

// TestSubmitResult_RefusesWorkIdOwnedByAnotherTenant is the core case: a
// component authenticated as one tenant names a work id belonging to another
// and submits a result for it.
func TestSubmitResult_RefusesWorkIdOwnedByAnotherTenant(t *testing.T) {
	env := newWorkIDEnv(t)
	workID := env.enqueueFor(t, victimTenant, "work-cross-tenant-1")

	ctx := auth.ContextWithTenantString(context.Background(), attackerTenant)
	resp, err := env.svc.SubmitResult(ctx, &componentpb.SubmitResultRequest{
		WorkId: workID,
		Result: []byte(`{"substituted":true}`),
	})

	require.Error(t, err, "a result for another tenant's work item must be refused")
	assert.Nil(t, resp)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	assert.False(t, env.mr.Exists(resultKey(victimTenant, workID)),
		"the victim's result slot must be untouched")
	assert.False(t, env.mr.Exists(resultKey(attackerTenant, workID)),
		"a refused submission must not write a result anywhere")
}

// TestSubmitResult_RefusalDoesNotRevealWhetherWorkIdExists checks that a work id
// belonging to someone else and a work id that was never issued are refused the
// same way, so the RPC cannot be used to enumerate live work ids.
func TestSubmitResult_RefusalDoesNotRevealWhetherWorkIdExists(t *testing.T) {
	env := newWorkIDEnv(t)
	realWorkID := env.enqueueFor(t, victimTenant, "work-real-1")

	ctx := auth.ContextWithTenantString(context.Background(), attackerTenant)

	_, foreignErr := env.svc.SubmitResult(ctx, &componentpb.SubmitResultRequest{
		WorkId: realWorkID,
		Result: []byte(`{}`),
	})
	_, unknownErr := env.svc.SubmitResult(ctx, &componentpb.SubmitResultRequest{
		WorkId: "work-was-never-issued",
		Result: []byte(`{}`),
	})

	require.Error(t, foreignErr)
	require.Error(t, unknownErr)
	assert.Equal(t, status.Code(foreignErr), status.Code(unknownErr),
		"an existing foreign work id and an unknown one must yield the same code")
	assert.Equal(t,
		status.Convert(foreignErr).Message()[:len("work_id ")],
		status.Convert(unknownErr).Message()[:len("work_id ")],
		"both refusals must use the same message shape")
}

// TestSubmitResult_AcceptsOwningTenant is the counterpart: the tenant the work
// was enqueued for still gets through, and its result lands in its own slot.
func TestSubmitResult_AcceptsOwningTenant(t *testing.T) {
	env := newWorkIDEnv(t)
	workID := env.enqueueFor(t, victimTenant, "work-owner-1")

	ctx := auth.ContextWithTenantString(context.Background(), victimTenant)
	resp, err := env.svc.SubmitResult(ctx, &componentpb.SubmitResultRequest{
		WorkId: workID,
		Result: []byte(`{"ok":true}`),
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, env.mr.Exists(resultKey(victimTenant, workID)),
		"the owner's result must be stored under the owner's namespace")
}

// TestSubmitResult_AcceptsSharedComponentIdentity covers the shared-deployment
// path: a _system component claims work from every tenant's stream, so it
// necessarily returns results for work it does not own.
func TestSubmitResult_AcceptsSharedComponentIdentity(t *testing.T) {
	env := newWorkIDEnv(t)
	workID := env.enqueueFor(t, victimTenant, "work-shared-1")

	// The reserved system tenant cannot be built from its raw string, so the
	// typed constant is used — the same route the daemon's auth layer takes.
	ctx := auth.ContextWithTenant(context.Background(), auth.SystemTenant)
	require.Equal(t, systemTenant, auth.TenantStringFromContext(ctx),
		"the context must actually carry the system tenant, or this test proves nothing")

	resp, err := env.svc.SubmitResult(ctx, &componentpb.SubmitResultRequest{
		WorkId: workID,
		Result: []byte(`{"ok":true}`),
	})

	require.NoError(t, err, "a shared component must still be able to return results")
	require.NotNil(t, resp)
	assert.True(t, env.mr.Exists(resultKey(victimTenant, workID)),
		"a shared component's result belongs to the tenant that enqueued the work")
}

// TestSubmitResult_RefusedWhenOwnershipCannotBeEstablished pins the closed
// default: with no work-context registry there is no way to tell whose work an
// id names, and an unanswerable question must not resolve to "allowed".
func TestSubmitResult_RefusedWhenOwnershipCannotBeEstablished(t *testing.T) {
	svc := NewComponentServiceServer(&noopRegistry{}, &noopWorkQueue{}, testLogger(), nil, nil, nil, nil)

	ctx := auth.ContextWithTenantString(context.Background(), attackerTenant)
	_, err := svc.SubmitResult(ctx, &componentpb.SubmitResultRequest{
		WorkId: "work-anything",
		Result: []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// ---------------------------------------------------------------------------
// Result key namespacing
// ---------------------------------------------------------------------------

// TestWorkQueue_ResultIsNamespacedByOwningTenant asserts the storage layout
// directly: the result slot carries the owning tenant, so the same work id
// under two tenants cannot name one shared key.
func TestWorkQueue_ResultIsNamespacedByOwningTenant(t *testing.T) {
	env := newWorkIDEnv(t)
	ctx := context.Background()
	workID := env.enqueueFor(t, victimTenant, "work-namespaced-1")

	require.NoError(t, env.queue.DeliverResult(ctx, workID, WorkResult{
		WorkID: workID,
		Result: []byte(`{"ok":true}`),
	}))

	assert.True(t, env.mr.Exists(resultKey(victimTenant, workID)),
		"result must be stored under the owning tenant")
	assert.False(t, env.mr.Exists("result:"+workID),
		"result must not be stored at a tenant-less key any caller could name")
}

// TestWorkQueue_RefusesResultForUnboundWorkId covers a work id that this queue
// never dispatched: there is no tenant to route it to, so it cannot be stored.
func TestWorkQueue_RefusesResultForUnboundWorkId(t *testing.T) {
	env := newWorkIDEnv(t)

	err := env.queue.DeliverResult(context.Background(), "work-never-enqueued", WorkResult{
		WorkID: "work-never-enqueued",
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWorkOwnerUnknown)
}

// ---------------------------------------------------------------------------
// SubmitFinding
// ---------------------------------------------------------------------------

// TestSubmitFinding_RefusesWorkIdOwnedByAnotherTenant covers the finding path:
// the work id chooses the mission a finding is attributed to, so a foreign id
// must not be accepted.
func TestSubmitFinding_RefusesWorkIdOwnedByAnotherTenant(t *testing.T) {
	env := newWorkIDEnv(t)
	workID := env.enqueueFor(t, victimTenant, "work-finding-1")

	ctx := auth.ContextWithTenantString(context.Background(), attackerTenant)
	resp, err := env.svc.SubmitFinding(ctx, &componentpb.SubmitFindingRequest{
		WorkId:  workID,
		Finding: []byte(`{"title":"planted"}`),
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestSubmitFinding_AllowsFindingWithoutAWorkItem keeps the legitimate
// tenant-ambient case working: no work id means no mission to attribute to, not
// a rejected submission.
func TestSubmitFinding_AllowsFindingWithoutAWorkItem(t *testing.T) {
	env := newWorkIDEnv(t)

	ctx := auth.ContextWithTenantString(context.Background(), attackerTenant)
	resp, err := env.svc.SubmitFinding(ctx, &componentpb.SubmitFindingRequest{
		Finding: []byte(`{"title":"ambient"}`),
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.FindingId)
}

// ---------------------------------------------------------------------------
// Mission attribution inside the finding submitter
// ---------------------------------------------------------------------------

// newRecordingFindingSubmitter builds a submitter over mr and returns a pointer
// to the mission id the World sink is handed, which is the value the work id
// controls.
func newRecordingFindingSubmitter(t *testing.T, sc *state.StateClient) (submitter *GraphRAGFindingSubmitter, seenMissionID *string) {
	t.Helper()

	var seenMission string
	sink := func(_ context.Context, _, missionID string, _ agent.Finding) {
		seenMission = missionID
	}
	return NewGraphRAGFindingSubmitter(sink, nil, sc, testLogger()), &seenMission
}

// TestFindingSubmitter_IgnoresWorkContextOfAnotherTenant checks the second half
// of the binding. The work-context hash is keyed by work id alone, so it must
// not hand back a mission to a tenant that does not own the work item.
func TestFindingSubmitter_IgnoresWorkContextOfAnotherTenant(t *testing.T) {
	env := newWorkIDEnv(t)
	submitter, seenMission := newRecordingFindingSubmitter(t, env.state)

	writeWorkContext(t, env.mr, "work-mission-1", "mission-of-victim", victimTenant)

	_, err := submitter.Submit(context.Background(), attackerTenant, "work-mission-1",
		`{"title":"planted"}`, "high", "planted")

	require.NoError(t, err, "the finding is still recorded under the submitter's own tenant")
	assert.Empty(t, *seenMission,
		"a finding must not be stamped with a mission resolved from another tenant's work context")
}

// TestFindingSubmitter_ResolvesMissionForOwningTenant is the counterpart: the
// owning tenant still gets its mission attribution.
func TestFindingSubmitter_ResolvesMissionForOwningTenant(t *testing.T) {
	env := newWorkIDEnv(t)
	submitter, seenMission := newRecordingFindingSubmitter(t, env.state)

	writeWorkContext(t, env.mr, "work-mission-2", "mission-of-victim", victimTenant)

	_, err := submitter.Submit(context.Background(), victimTenant, "work-mission-2",
		`{"title":"genuine"}`, "high", "genuine")

	require.NoError(t, err)
	assert.Equal(t, "mission-of-victim", *seenMission,
		"the owning tenant's finding must still attach to its mission")
}

// ---------------------------------------------------------------------------
// The owner binding itself
// ---------------------------------------------------------------------------

// TestWorkOwnerBinding_RoundTrip covers the binding primitives directly,
// including the arguments that must be refused outright.
func TestWorkOwnerBinding_RoundTrip(t *testing.T) {
	env := newWorkIDEnv(t)
	ctx := context.Background()
	client := redis.NewClient(&redis.Options{Addr: env.mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	require.NoError(t, bindWorkOwner(ctx, client, "work-bind-1", victimTenant))

	owner, err := lookupWorkOwner(ctx, client, "work-bind-1")
	require.NoError(t, err)
	assert.Equal(t, victimTenant, owner)

	assert.True(t, env.mr.Exists(workOwnerKey("work-bind-1")),
		"the binding must live at the documented key")

	_, unknownErr := lookupWorkOwner(ctx, client, "work-never-bound")
	require.ErrorIs(t, unknownErr, ErrWorkOwnerUnknown)

	_, emptyErr := lookupWorkOwner(ctx, client, "")
	require.ErrorIs(t, emptyErr, ErrWorkOwnerUnknown)

	require.Error(t, bindWorkOwner(ctx, client, "", victimTenant),
		"a binding with no work id names nothing")
	require.Error(t, bindWorkOwner(ctx, client, "work-bind-2", ""),
		"a binding with no tenant grants nothing and must not be written")
	assert.False(t, env.mr.Exists(workOwnerKey("work-bind-2")))
}

// TestTenantMayActOnWork enumerates the entitlement rule so the shared-component
// carve-out cannot widen unnoticed.
func TestTenantMayActOnWork(t *testing.T) {
	cases := []struct {
		name          string
		caller, owner string
		want          bool
	}{
		{"owner acts on its own work", victimTenant, victimTenant, true},
		{"another tenant may not", attackerTenant, victimTenant, false},
		{"shared component may act for any tenant", systemTenant, victimTenant, true},
		{"a tenant may not act on shared work", attackerTenant, systemTenant, false},
		{"unauthenticated caller may not", "", victimTenant, false},
		{"unowned work grants nothing", attackerTenant, "", false},
		{"unowned work grants nothing even to the shared identity", systemTenant, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tenantMayActOnWork(tc.caller, tc.owner))
		})
	}
}

// TestWorkQueue_EnqueueFailsWhenTheOwnerCannotBeRecorded pins the closed
// default at dispatch time: work whose result could not later be attributed
// must not be handed out at all.
func TestWorkQueue_EnqueueFailsWhenTheOwnerCannotBeRecorded(t *testing.T) {
	env := newWorkIDEnv(t)
	env.mr.Close() // Redis is gone; the binding cannot be written.

	_, err := env.queue.Enqueue(context.Background(), victimTenant, "tool", "nmap", WorkItem{
		WorkID:   "work-unbindable",
		WorkType: "execute",
	})

	require.Error(t, err)
}

// TestWorkQueue_RefusesToWaitOnAnUnboundWorkId is the wait-side counterpart of
// the deliver-side refusal.
func TestWorkQueue_RefusesToWaitOnAnUnboundWorkId(t *testing.T) {
	env := newWorkIDEnv(t)

	result, err := env.queue.WaitForResult(context.Background(), "work-never-enqueued", time.Second)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrWorkOwnerUnknown)
}

// TestSubmitResult_RefusesWhenTheOwnerLookupFails covers the third outcome of
// the check: Redis is unreachable, so entitlement is unknown rather than
// granted.
func TestSubmitResult_RefusesWhenTheOwnerLookupFails(t *testing.T) {
	env := newWorkIDEnv(t)
	workID := env.enqueueFor(t, victimTenant, "work-lookup-fails")
	env.mr.Close()

	ctx := auth.ContextWithTenantString(context.Background(), victimTenant)
	_, err := env.svc.SubmitResult(ctx, &componentpb.SubmitResultRequest{
		WorkId: workID,
		Result: []byte(`{}`),
	})

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// Graph scope
// ---------------------------------------------------------------------------

// captureDiscoveryProcessor records the execution context a discovery write is
// scoped by, which is the value the work id used to control.
type captureDiscoveryProcessor struct {
	got chan ingest.ExecContext
}

func newCaptureDiscoveryProcessor() *captureDiscoveryProcessor {
	return &captureDiscoveryProcessor{got: make(chan ingest.ExecContext, 1)}
}

func (p *captureDiscoveryProcessor) Process(_ context.Context, execCtx ingest.ExecContext, _ *graphragpb.DiscoveryResult) (interface{}, error) {
	select {
	case p.got <- execCtx:
	default:
	}
	return nil, nil
}

// discoveryPayload builds tool-response bytes carrying a DiscoveryResult at the
// reserved field 100, which is what SubmitResult scans for.
func discoveryPayload(t *testing.T) []byte {
	t.Helper()

	inner, err := proto.Marshal(&graphragpb.DiscoveryResult{
		Hosts: []*graphragpb.Host{{Ip: "10.0.0.1"}},
	})
	require.NoError(t, err)

	out := protowire.AppendTag(nil, 100, protowire.BytesType)
	return protowire.AppendBytes(out, inner)
}

// TestSubmitResult_ScopesDiscoveryToTheWorkOwner checks the graph side of the
// binding: a shared component's discovery write is stamped with the tenant that
// owns the work, not with the shared identity that returned it, and never with
// a zero tenant.
func TestSubmitResult_ScopesDiscoveryToTheWorkOwner(t *testing.T) {
	env := newWorkIDEnv(t)
	proc := newCaptureDiscoveryProcessor()
	env.svc.WithDiscoveryProcessor(proc)

	workID := env.enqueueFor(t, victimTenant, "work-discovery-1")

	ctx := auth.ContextWithTenant(context.Background(), auth.SystemTenant)
	_, err := env.svc.SubmitResult(ctx, &componentpb.SubmitResultRequest{
		WorkId: workID,
		Result: discoveryPayload(t),
	})
	require.NoError(t, err)

	select {
	case execCtx := <-proc.got:
		assert.Equal(t, victimTenant, execCtx.TenantID.String(),
			"the graph write must carry the work item's owner")
		assert.Equal(t, workID, execCtx.MissionRunID)
	case <-time.After(5 * time.Second):
		t.Fatal("discovery was never processed")
	}
}

// TestSubmitResult_SkipsDiscoveryWhenTheOwnerIsNotGraphAddressable covers work
// enqueued under the reserved platform tenant, which has no tenant graph to
// write into: the write is skipped rather than performed owner-less.
func TestSubmitResult_SkipsDiscoveryWhenTheOwnerIsNotGraphAddressable(t *testing.T) {
	env := newWorkIDEnv(t)
	proc := newCaptureDiscoveryProcessor()
	env.svc.WithDiscoveryProcessor(proc)

	workID := env.enqueueFor(t, systemTenant, "work-discovery-2")

	ctx := auth.ContextWithTenant(context.Background(), auth.SystemTenant)
	_, err := env.svc.SubmitResult(ctx, &componentpb.SubmitResultRequest{
		WorkId: workID,
		Result: discoveryPayload(t),
	})
	require.NoError(t, err)

	select {
	case execCtx := <-proc.got:
		t.Fatalf("discovery must not be processed without an addressable owner, got %+v", execCtx)
	case <-time.After(300 * time.Millisecond):
	}
}

// ---------------------------------------------------------------------------
// PollWork
// ---------------------------------------------------------------------------

// pollRegistry reports one component so PollWork can route a claim to it.
type pollRegistry struct {
	noopRegistry
	info ComponentInfo
}

func (r *pollRegistry) ListTenantComponents(_ context.Context, _ string) ([]ComponentInfo, error) {
	return []ComponentInfo{r.info}, nil
}

// TestPollWork_RecordsTheTenantTheWorkWasClaimedFrom covers the mapping a
// shared component leaves behind. Its own identity is not the work item's
// tenant, and recording it as such is what let a later finding resolve a
// mission through the wrong tenant.
func TestPollWork_RecordsTheTenantTheWorkWasClaimedFrom(t *testing.T) {
	env := newWorkIDEnv(t)
	env.svc.registry = &pollRegistry{info: ComponentInfo{
		Kind: "tool", Name: "nmap", InstanceID: "inst-shared",
	}}

	// Work enqueued by a tenant, waiting on that tenant's stream.
	_, err := env.queue.Enqueue(context.Background(), victimTenant, "tool", "nmap", WorkItem{
		WorkID:   "work-poll-1",
		WorkType: "execute",
		Context:  map[string]string{"mission_id": "mission-1"},
	})
	require.NoError(t, err)

	// A shared deployment polls across every tenant's stream.
	ctx := auth.ContextWithTenant(context.Background(), auth.SystemTenant)
	resp, err := env.svc.PollWork(ctx, &componentpb.PollWorkRequest{
		InstanceId: "inst-shared",
		TimeoutMs:  100,
	})
	require.NoError(t, err)
	require.Equal(t, "work-poll-1", resp.WorkId)

	assert.Equal(t, victimTenant, env.mr.HGet(workContextKey("work-poll-1"), workContextTenantField),
		"the work context must name the tenant the item was claimed from, not the poller")
}

// TestPollWork_RecordsTheCallersTenantForItsOwnStream is the single-tenant
// counterpart: a tenant-scoped component polls its own stream and is the owner.
func TestPollWork_RecordsTheCallersTenantForItsOwnStream(t *testing.T) {
	env := newWorkIDEnv(t)
	env.svc.registry = &pollRegistry{info: ComponentInfo{
		Kind: "tool", Name: "nmap", InstanceID: "inst-own",
	}}

	_, err := env.queue.Enqueue(context.Background(), victimTenant, "tool", "nmap", WorkItem{
		WorkID:   "work-poll-2",
		WorkType: "execute",
		Context:  map[string]string{"mission_id": "mission-2"},
	})
	require.NoError(t, err)

	ctx := auth.ContextWithTenantString(context.Background(), victimTenant)
	resp, err := env.svc.PollWork(ctx, &componentpb.PollWorkRequest{
		InstanceId: "inst-own",
		TimeoutMs:  100,
	})
	require.NoError(t, err)
	require.Equal(t, "work-poll-2", resp.WorkId)

	assert.Equal(t, victimTenant, env.mr.HGet(workContextKey("work-poll-2"), workContextTenantField))
}

// ---------------------------------------------------------------------------
// Dispatch round-trip
// ---------------------------------------------------------------------------

// dispatchRegistry reports one discoverable component for the dispatch RPCs.
type dispatchRegistry struct {
	noopRegistry
	info ComponentInfo
}

func (r *dispatchRegistry) Discover(_ context.Context, _, _, _ string) ([]ComponentInfo, error) {
	return []ComponentInfo{r.info}, nil
}

// TestCallTool_WaitsOnTheWorkIdTheComponentEchoesBack proves the dispatch
// round-trip closes on the id the component actually sees. Enqueue returns the
// Redis stream message id, so waiting on that value could never be satisfied by
// a component replying with the work id it was handed.
func TestCallTool_WaitsOnTheWorkIdTheComponentEchoesBack(t *testing.T) {
	env := newWorkIDEnv(t)
	env.svc.registry = &dispatchRegistry{info: ComponentInfo{
		Kind: "tool", Name: "nmap", InstanceID: "inst-tool",
	}}

	// Stand in for the component: claim the work item and answer with the work
	// id it was handed, exactly as a polling component does.
	delivered := make(chan error, 1)
	go func() {
		ctx := context.Background()
		for range 100 {
			item, claimErr := env.queue.Claim(ctx, victimTenant, "tool", "nmap", "inst-tool", 100*time.Millisecond)
			if claimErr != nil {
				delivered <- claimErr
				return
			}
			if item == nil {
				continue
			}
			delivered <- env.queue.DeliverResult(ctx, item.WorkID, WorkResult{
				WorkID: item.WorkID,
				Result: []byte(`{"ports":[80]}`),
			})
			return
		}
		delivered <- nil
	}()

	ctx := auth.ContextWithTenantString(context.Background(), victimTenant)
	resp, err := env.svc.CallTool(ctx, &componentpb.CallToolRequest{
		ToolName:  "nmap",
		InputJson: `{"target":"10.0.0.1"}`,
		TimeoutMs: 10000,
	})

	require.NoError(t, <-delivered, "the stand-in component must deliver its result")
	require.NoError(t, err, "CallTool must observe the result the component delivered")
	require.NotNil(t, resp)
}
