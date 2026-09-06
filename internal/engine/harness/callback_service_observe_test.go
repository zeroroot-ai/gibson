// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// observeMockHarness is an AgentHarness stub carrying the two server-side facts
// the Observe path reads: the mission record (tenant + id) and the mission's
// target (the scope).
type observeMockHarness struct {
	DefaultAgentHarness
	missionID types.ID
	tenantID  string
	targetID  types.ID
}

func (m *observeMockHarness) Mission() MissionContext {
	return MissionContext{ID: m.missionID, TenantID: m.tenantID}
}

func (m *observeMockHarness) Target() TargetInfo {
	return TargetInfo{ID: m.targetID}
}

func (m *observeMockHarness) Workspace() workspace.Workspace { return nil }
func (m *observeMockHarness) Workspaces() map[string]workspace.Workspace {
	return map[string]workspace.Workspace{}
}

// observeCapture records everything a sink was handed.
type observeCapture struct {
	attr ObservationAttribution
	req  *harnesspb.ObserveRequest
}

// newObserveService registers one harness under (missionID, "recon-agent") and
// returns a service whose observation sink appends into got.
func newObserveService(t *testing.T, h *observeMockHarness, got *[]observeCapture) *HarnessCallbackService {
	t.Helper()
	registry := NewCallbackHarnessRegistry()
	registry.Register(h.missionID.String(), "recon-agent", h)
	return NewHarnessCallbackServiceWithRegistry(
		slog.New(slog.DiscardHandler),
		registry,
		WithObservationSink(func(_ context.Context, attr ObservationAttribution, req *harnesspb.ObserveRequest) error {
			*got = append(*got, observeCapture{attr: attr, req: req})
			return nil
		}),
	)
}

func hostObservation(missionID, address string) *harnesspb.ObserveRequest {
	return &harnesspb.ObserveRequest{
		Context: &harnesspb.ContextInfo{MissionId: missionID, AgentName: "recon-agent"},
		Observation: &harnesspb.ObserveRequest_Host{
			Host: &harnesspb.HostObservation{Address: address},
		},
	}
}

// TestObserve_AttributionComesFromTheMissionRecord is the core of gibson#1256:
// the tenant an observation lands in and the scope it is keyed under are both
// read off the daemon's mission record, not off the payload and not off a
// process-wide default.
//
// The scope assertion is the load-bearing one: it must be the mission's TARGET,
// and must differ from the mission id the caller sent. Before this change the
// sink derived scope from req.Context.MissionId — a caller-supplied string.
func TestObserve_AttributionComesFromTheMissionRecord(t *testing.T) {
	var got []observeCapture
	svc := newObserveService(t, &observeMockHarness{
		missionID: "mission-A",
		tenantID:  "acme",
		targetID:  "target-net-a",
	}, &got)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	resp, err := svc.Observe(ctx, hostObservation("mission-A", "10.0.0.1"))
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Error)

	require.Len(t, got, 1)
	attr := got[0].attr
	assert.Equal(t, "acme", attr.Tenant, "tenant must be the mission record's tenant")
	assert.Equal(t, "target-net-a", attr.ScopeID, "scope must be the mission's target")
	assert.Equal(t, "mission-A", attr.MissionID, "the write stays attributable to its mission")
	assert.NotEqual(t, attr.MissionID, attr.ScopeID,
		"scope must come from the target definition, not from the caller-supplied mission id")
}

// TestObserve_ForeignTenantIsUnrepresentableAndUnreachable covers the "cannot
// name a foreign tenant" criterion from both ends.
//
// There is no field to name one — asserted separately by
// TestObserveRequest_CannotCarryTenantOrScope — and an agent that instead points
// at another tenant's mission is refused outright rather than having its write
// land anywhere.
func TestObserve_ForeignTenantIsUnrepresentableAndUnreachable(t *testing.T) {
	var got []observeCapture
	svc := newObserveService(t, &observeMockHarness{
		missionID: "mission-A",
		tenantID:  "acme",
		targetID:  "target-net-a",
	}, &got)

	// Authenticated as "evilcorp", naming acme's mission.
	ctx := auth.ContextWithTenantString(context.Background(), "evilcorp")
	_, err := svc.Observe(ctx, hostObservation("mission-A", "10.0.0.1"))

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, got, "a cross-tenant observation must not reach the World at all")
}

// TestObserve_NoTenantInContext_Rejected: an unauthenticated caller has no
// mission to be attributed to. Agents outlive the session, so the bar is not
// "a user was present" — but it is still "reached us through a mission".
func TestObserve_NoTenantInContext_Rejected(t *testing.T) {
	var got []observeCapture
	svc := newObserveService(t, &observeMockHarness{
		missionID: "mission-A",
		tenantID:  "acme",
		targetID:  "target-net-a",
	}, &got)

	_, err := svc.Observe(context.Background(), hostObservation("mission-A", "10.0.0.1"))

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, got)
}

// TestObserve_NilRequest_Rejected: nothing to attribute, and nothing to
// dereference. The handler must say so rather than panic the callback listener,
// which is the daemon's internet-facing surface for customer-run agents.
func TestObserve_NilRequest_Rejected(t *testing.T) {
	var got []observeCapture
	svc := newObserveService(t, &observeMockHarness{
		missionID: "mission-A",
		tenantID:  "acme",
		targetID:  "target-net-a",
	}, &got)

	_, err := svc.Observe(auth.ContextWithTenantString(context.Background(), "acme"), nil)

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, got)
}

// TestObserve_UnknownMission_Rejected: a mission id that names no registered
// harness resolves no mission record, so there is nothing to attribute the write
// to. Previously such a request was accepted and written under the daemon's
// process-wide tenant with the unknown id as its scope.
func TestObserve_UnknownMission_Rejected(t *testing.T) {
	var got []observeCapture
	svc := newObserveService(t, &observeMockHarness{
		missionID: "mission-A",
		tenantID:  "acme",
		targetID:  "target-net-a",
	}, &got)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	_, err := svc.Observe(ctx, hostObservation("mission-does-not-exist", "10.0.0.1"))

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Empty(t, got)
}

// TestObserve_UnresolvableScope_RejectedNotDefaulted: a mission whose record
// carries no target yields no scope, and the observation is refused.
//
// Defaulting to "" would be the dangerous outcome, not the safe one: host
// identity is the (ScopeID, Address) coordinate, so an empty scope is a single
// shared coordinate space into which every network collapses.
func TestObserve_UnresolvableScope_RejectedNotDefaulted(t *testing.T) {
	var got []observeCapture
	svc := newObserveService(t, &observeMockHarness{
		missionID: "mission-A",
		tenantID:  "acme",
		targetID:  "", // broken mission record: target_id is required at creation
	}, &got)

	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	_, err := svc.Observe(ctx, hostObservation("mission-A", "10.0.0.1"))

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "no scope can be resolved")
	assert.Empty(t, got, "an observation with no scope must not be written under an empty one")
}

// TestObserveRequest_CannotCarryTenantOrScope asserts the unrepresentability
// half of the design: there is no field on the emit message for a tenant or a
// scope, in the request or in its context, so cross-scope creation cannot be
// expressed rather than being expressed and rejected.
//
// Adding such a field — here or in the SDK proto this repo pins — turns this
// red, which is the point: it is the only thing standing between "no field" and
// "a field somebody validates".
func TestObserveRequest_CannotCarryTenantOrScope(t *testing.T) {
	forbidden := []string{"tenant", "scope"}

	var walk func(d protoreflect.MessageDescriptor, path string, depth int)
	seen := map[protoreflect.FullName]bool{}
	walk = func(d protoreflect.MessageDescriptor, path string, depth int) {
		if depth > 4 || seen[d.FullName()] {
			return
		}
		seen[d.FullName()] = true
		fields := d.Fields()
		for i := range fields.Len() {
			f := fields.Get(i)
			name := string(f.Name())
			for _, bad := range forbidden {
				assert.NotContains(t, name, bad,
					"%s.%s: tenant and scope are resolved server-side and must have no field on the emit path (ADR-0012)",
					path, name)
			}
			if f.Kind() == protoreflect.MessageKind && !f.IsMap() {
				walk(f.Message(), path+"."+name, depth+1)
			}
		}
	}
	walk((&harnesspb.ObserveRequest{}).ProtoReflect().Descriptor(), "ObserveRequest", 0)

	// Guard the guard: the walk must actually have visited the payload, not
	// silently traversed nothing.
	require.True(t, seen["gibson.harness.v1.HostObservation"],
		"walk did not reach HostObservation; the field scan proves nothing")
	require.True(t, seen["gibson.harness.v1.ContextInfo"],
		"walk did not reach ContextInfo; the field scan proves nothing")
}

// TestObservationAttribution_ScopeErrorNamesTheMission keeps the rejection
// legible to whoever reads the log: the error says which mission is broken.
func TestObservationAttribution_ScopeErrorNamesTheMission(t *testing.T) {
	_, err := observationAttribution(&observeMockHarness{
		missionID: "mission-Z", tenantID: "acme", targetID: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mission-Z",
		"the rejection must name the mission")
}
