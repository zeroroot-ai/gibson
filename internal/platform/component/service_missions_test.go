// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// service_missions_test.go covers the eight mission RPCs (gibson#1358), the
// hard-cut replacement for the FailedPrecondition stubs #1201 shipped while
// the origination decisions were open.
//
// Two things get deliberate, separate treatment:
//
//   - The capability gate on EVERY one of the eight, not just CreateMission.
//     A table drives all eight through each failure mode, so a handler added
//     later that forgets the gate fails a test that already exists.
//   - One call over a REAL gRPC server. Asserting a method exists, or that it
//     no longer answers Unimplemented, proves nothing here:
//     UnimplementedComponentServiceServer is embedded, so a method that was
//     never wired still dispatches and answers — and a method deleted from the
//     wire answers the same way. The over-the-wire test therefore asserts a
//     POSITIVE result produced by this package's own handler, alongside a
//     control call on the same connection that genuinely does answer
//     Unimplemented, so the two are known to be distinguishable through the
//     same stack.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zeroroot-ai/gibson/internal/platform/capname"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// recordingMissionManager records what the handlers hand the seam, so the
// tests can assert on the authority-bearing values (tenant, parent, grant)
// rather than only on the status code that came back.
type recordingMissionManager struct {
	originated []OriginateMissionRequest
	tenants    []string
	missionIDs []string
	payload    []byte
	err        error
}

func (m *recordingMissionManager) OriginateMission(_ context.Context, req OriginateMissionRequest) ([]byte, error) {
	m.originated = append(m.originated, req)
	if m.err != nil {
		return nil, m.err
	}
	return m.payload, nil
}

func (m *recordingMissionManager) RunMission(_ context.Context, tenant, missionID string, _ []byte) error {
	m.tenants = append(m.tenants, tenant)
	m.missionIDs = append(m.missionIDs, missionID)
	return m.err
}

func (m *recordingMissionManager) GetMissionStatus(_ context.Context, tenant, missionID string) ([]byte, error) {
	m.tenants = append(m.tenants, tenant)
	m.missionIDs = append(m.missionIDs, missionID)
	return m.payload, m.err
}

func (m *recordingMissionManager) WaitForMission(_ context.Context, tenant, missionID string, _ int64) ([]byte, error) {
	m.tenants = append(m.tenants, tenant)
	m.missionIDs = append(m.missionIDs, missionID)
	return m.payload, m.err
}

func (m *recordingMissionManager) ListMissions(_ context.Context, tenant string, _ []byte) ([]byte, error) {
	m.tenants = append(m.tenants, tenant)
	return m.payload, m.err
}

func (m *recordingMissionManager) CancelMission(_ context.Context, tenant, missionID string) error {
	m.tenants = append(m.tenants, tenant)
	m.missionIDs = append(m.missionIDs, missionID)
	return m.err
}

func (m *recordingMissionManager) GetMissionResults(_ context.Context, tenant, missionID string) ([]byte, error) {
	m.tenants = append(m.tenants, tenant)
	m.missionIDs = append(m.missionIDs, missionID)
	return m.payload, m.err
}

func (m *recordingMissionManager) GetMissionRunHistory(_ context.Context, tenant, missionID string) ([]byte, error) {
	m.tenants = append(m.tenants, tenant)
	m.missionIDs = append(m.missionIDs, missionID)
	return m.payload, m.err
}

// originateChecker grants capname.MissionOriginate under a known grant id.
func originateChecker(grantID string) *mockCapabilityChecker {
	return &mockCapabilityChecker{
		granted: map[string]bool{capname.MissionOriginate: true},
		grantID: grantID,
	}
}

// missionServer builds a service with the mission seam and capability
// checker wired.
func missionServer(mgr MissionManager, checker CapabilityChecker) *ComponentServiceServer {
	svc := newParityServer().WithMissionManager(mgr)
	if checker != nil {
		svc.WithCapabilityChecker(checker)
	}
	return svc
}

// missionCallers drives every mission RPC through one closure so a gate test
// covers all eight instead of whichever one someone remembered.
func missionCallers(svc *ComponentServiceServer) map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"CreateMission": func(ctx context.Context) error {
			_, err := svc.CreateMission(ctx, &componentpb.CreateMissionRequest{})
			return err
		},
		"RunMission": func(ctx context.Context) error {
			_, err := svc.RunMission(ctx, &componentpb.RunMissionRequest{MissionId: "m-1"})
			return err
		},
		"GetMissionStatus": func(ctx context.Context) error {
			_, err := svc.GetMissionStatus(ctx, &componentpb.GetMissionStatusRequest{MissionId: "m-1"})
			return err
		},
		"WaitMission": func(ctx context.Context) error {
			_, err := svc.WaitMission(ctx, &componentpb.WaitMissionRequest{MissionId: "m-1"})
			return err
		},
		"ListMissions": func(ctx context.Context) error {
			_, err := svc.ListMissions(ctx, &componentpb.ListMissionsRequest{})
			return err
		},
		"CancelMission": func(ctx context.Context) error {
			_, err := svc.CancelMission(ctx, &componentpb.CancelMissionRequest{MissionId: "m-1"})
			return err
		},
		"GetMissionResults": func(ctx context.Context) error {
			_, err := svc.GetMissionResults(ctx, &componentpb.GetMissionResultsRequest{MissionId: "m-1"})
			return err
		},
		"GetMissionRunHistory": func(ctx context.Context) error {
			_, err := svc.GetMissionRunHistory(ctx, &componentpb.GetMissionRunHistoryRequest{WorkId: "w-1"})
			return err
		},
	}
}

// ---------------------------------------------------------------------------
// The capability gate, on all eight
// ---------------------------------------------------------------------------

func TestMissionRPCs_RequireATenant(t *testing.T) {
	svc := missionServer(&recordingMissionManager{}, originateChecker("grant-1"))
	for name, call := range missionCallers(svc) {
		t.Run(name, func(t *testing.T) {
			err := call(context.Background())
			require.Error(t, err)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
}

func TestMissionRPCs_RefuseTheSystemTenant(t *testing.T) {
	svc := missionServer(&recordingMissionManager{}, originateChecker("grant-1"))
	ctx := auth.ContextWithTenantString(context.Background(), auth.SystemTenantString)
	for name, call := range missionCallers(svc) {
		t.Run(name, func(t *testing.T) {
			err := call(ctx)
			require.Error(t, err)
			assert.Equal(t, codes.Unauthenticated, status.Code(err),
				"the shared _system tenant is not a tenant whose missions anyone may run")
		})
	}
}

func TestMissionRPCs_FailClosedWhenTheCheckerIsNotWired(t *testing.T) {
	// No capability checker: the gate cannot be evaluated, which is never
	// the same thing as the gate being open.
	svc := missionServer(&recordingMissionManager{}, nil)
	for name, call := range missionCallers(svc) {
		t.Run(name, func(t *testing.T) {
			err := call(componentCtx("agent_principal:abc"))
			require.Error(t, err)
			assert.Equal(t, codes.Unavailable, status.Code(err))
		})
	}
}

func TestMissionRPCs_FailClosedWhenTheSeamIsNotWired(t *testing.T) {
	svc := newParityServer().WithCapabilityChecker(originateChecker("grant-1"))
	for name, call := range missionCallers(svc) {
		t.Run(name, func(t *testing.T) {
			err := call(componentCtx("agent_principal:abc"))
			require.Error(t, err)
			assert.Equal(t, codes.Unavailable, status.Code(err))
		})
	}
}

func TestMissionRPCs_DenyWithoutTheOriginateCapability(t *testing.T) {
	// The caller holds mission:delegate — the OTHER bit. Holding the
	// lower-trust capability must not open the higher-trust surface.
	checker := &mockCapabilityChecker{granted: map[string]bool{capname.MissionDelegate: true}}
	mgr := &recordingMissionManager{}
	svc := missionServer(mgr, checker)

	for name, call := range missionCallers(svc) {
		t.Run(name, func(t *testing.T) {
			err := call(componentCtx("agent_principal:abc"))
			require.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
		})
	}
	assert.Empty(t, mgr.tenants, "a denied call must not reach the mission store")
	assert.Empty(t, mgr.originated, "a denied call must not reach the mission store")
}

func TestMissionRPCs_DenyWhenTheCheckerErrors(t *testing.T) {
	checker := &mockCapabilityChecker{err: errors.New("postgres is down")}
	svc := missionServer(&recordingMissionManager{}, checker)
	for name, call := range missionCallers(svc) {
		t.Run(name, func(t *testing.T) {
			err := call(componentCtx("agent_principal:abc"))
			require.Error(t, err)
			assert.Equal(t, codes.Internal, status.Code(err))
		})
	}
}

func TestMissionRPCs_DenyWithoutAnIdentity(t *testing.T) {
	svc := missionServer(&recordingMissionManager{}, originateChecker("grant-1"))
	// Tenant but no identity: the tenant alone cannot carry a capability.
	ctx := auth.ContextWithTenantString(context.Background(), "test-tenant")
	for name, call := range missionCallers(svc) {
		t.Run(name, func(t *testing.T) {
			err := call(ctx)
			require.Error(t, err)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
}

func TestMissionRPCs_CheckTheOriginateCapabilityForTheCallingPrincipal(t *testing.T) {
	checker := originateChecker("grant-1")
	svc := missionServer(&recordingMissionManager{}, checker)

	for name, call := range missionCallers(svc) {
		t.Run(name, func(t *testing.T) {
			checker.calls = nil
			_ = call(componentCtx("agent_principal:xyz"))

			require.Len(t, checker.calls, 1)
			assert.Equal(t, capname.MissionOriginate, checker.calls[0].capability)
			assert.Equal(t, "agent_principal:xyz", checker.calls[0].principal)
			assert.Equal(t, "test-tenant", checker.calls[0].tenant)
		})
	}
}

// ---------------------------------------------------------------------------
// CreateMission: what the handler hands the seam
// ---------------------------------------------------------------------------

func TestCreateMission_PassesTheVerifiedTenantPrincipalAndGrant(t *testing.T) {
	mgr := &recordingMissionManager{payload: []byte(`{"id":"child"}`)}
	svc := missionServer(mgr, originateChecker("grant-abc"))

	resp, err := svc.CreateMission(componentCtx("agent_principal:abc"), &componentpb.CreateMissionRequest{
		MissionDefinitionJson: []byte(`{"name":"child"}`),
		TargetId:              "target-1",
	})

	require.NoError(t, err)
	assert.JSONEq(t, `{"id":"child"}`, string(resp.GetMissionJson()))

	require.Len(t, mgr.originated, 1)
	got := mgr.originated[0]
	assert.Equal(t, "agent_principal:abc", got.Principal)
	assert.Equal(t, "grant-abc", got.GrantID,
		"lineage must record the grant the SAME lookup authorized the call with")
	assert.Equal(t, "target-1", got.TargetID)
	assert.JSONEq(t, `{"name":"child"}`, string(got.DefinitionJSON))
}

func TestCreateMission_ResolvesNoParentFromAnUnknownWorkID(t *testing.T) {
	// No work-context registry is wired, so nothing resolves: the parent
	// arrives empty and the seam is the one that refuses. What matters here
	// is that the handler does not pass the caller's work id THROUGH as a
	// parent mission id.
	mgr := &recordingMissionManager{payload: []byte(`{}`)}
	svc := missionServer(mgr, originateChecker("grant-1"))

	_, err := svc.CreateMission(componentCtx("agent_principal:abc"), &componentpb.CreateMissionRequest{
		WorkId: "some-other-tenants-work-id",
	})

	require.NoError(t, err)
	require.Len(t, mgr.originated, 1)
	assert.Empty(t, mgr.originated[0].ParentMissionID,
		"an unresolvable work id must not become a parent mission id")
	assert.Equal(t, "some-other-tenants-work-id", mgr.originated[0].ParentWorkID,
		"the raw work id is still recorded as lineage — it is just not authority")
}

func TestCreateMission_SurfacesTheSeamsOwnStatusCode(t *testing.T) {
	// The origination policy's refusals (scope widening, exhausted budget)
	// arrive as gRPC statuses and must not be flattened into Internal.
	mgr := &recordingMissionManager{err: status.Error(codes.PermissionDenied, "scope widening")}
	svc := missionServer(mgr, originateChecker("grant-1"))

	_, err := svc.CreateMission(componentCtx("agent_principal:abc"), &componentpb.CreateMissionRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCreateMission_WrapsANonStatusErrorAsInternal(t *testing.T) {
	mgr := &recordingMissionManager{err: errors.New("something unexpected")}
	svc := missionServer(mgr, originateChecker("grant-1"))

	_, err := svc.CreateMission(componentCtx("agent_principal:abc"), &componentpb.CreateMissionRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestGetMissionRunHistory_RefusesAWorkIDThatResolvesToNoMission(t *testing.T) {
	mgr := &recordingMissionManager{payload: []byte(`[]`)}
	svc := missionServer(mgr, originateChecker("grant-1"))

	_, err := svc.GetMissionRunHistory(componentCtx("agent_principal:abc"),
		&componentpb.GetMissionRunHistoryRequest{WorkId: "not-mine"})

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Empty(t, mgr.missionIDs,
		"an unresolvable work id must never reach the run store as a mission id")
}

// ---------------------------------------------------------------------------
// Over the wire
// ---------------------------------------------------------------------------

// startMissionGRPCServer registers a real ComponentServiceServer on a real
// grpc.Server over bufconn, with an interceptor that stamps the identity the
// daemon's own interceptor would have stamped from ext-authz's headers.
func startMissionGRPCServer(t *testing.T, svc *ComponentServiceServer, subject string) componentpb.ComponentServiceClient {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer(grpc.UnaryInterceptor(
		func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			return handler(componentCtxFrom(ctx, subject), req)
		},
	))
	componentpb.RegisterComponentServiceServer(srv, svc)

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return componentpb.NewComponentServiceClient(conn)
}

// componentCtxFrom stamps tenant + identity onto an incoming server context.
func componentCtxFrom(ctx context.Context, subject string) context.Context {
	ctx = auth.ContextWithTenantString(ctx, "test-tenant")
	tenant, err := auth.NewTenantID("test-tenant")
	if err != nil {
		panic(err)
	}
	return auth.WithIdentity(ctx, auth.Identity{Subject: subject, Tenant: tenant})
}

func TestCreateMission_OverTheWire(t *testing.T) {
	ctx := context.Background()
	mgr := &recordingMissionManager{payload: []byte(`{"id":"child-42","status":"pending"}`)}
	client := startMissionGRPCServer(t,
		missionServer(mgr, originateChecker("grant-wire")),
		"agent_principal:wire")

	// A control call on the SAME connection, to a method that genuinely
	// exists on the service and genuinely answers Unimplemented because its
	// seam is nil. Without it, "CreateMission returned something other than
	// Unimplemented" would prove nothing about whether the wire can even
	// produce Unimplemented here.
	_, controlErr := client.GetTaxonomySchema(ctx, &componentpb.GetTaxonomySchemaRequest{})
	require.Error(t, controlErr)
	require.Equal(t, codes.Unimplemented, status.Code(controlErr),
		"control: an unwired seam must still answer Unimplemented over this same server")

	resp, err := client.CreateMission(ctx, &componentpb.CreateMissionRequest{
		MissionDefinitionJson: []byte(`{"name":"wire child"}`),
		TargetId:              "t-1",
	})

	// The positive assertion: the payload this package's handler produced
	// came back over a real connection, through real service registration.
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(resp.GetMissionJson(), &got))
	assert.Equal(t, "child-42", got["id"])

	// And the authority-bearing values were taken from the verified identity
	// on the server side, not from anything the client could set.
	require.Len(t, mgr.originated, 1)
	assert.Equal(t, "agent_principal:wire", mgr.originated[0].Principal)
	assert.Equal(t, "grant-wire", mgr.originated[0].GrantID)
}

func TestCreateMission_OverTheWire_DeniedWithoutTheCapability(t *testing.T) {
	mgr := &recordingMissionManager{payload: []byte(`{}`)}
	client := startMissionGRPCServer(t,
		missionServer(mgr, &mockCapabilityChecker{}), // grants nothing
		"agent_principal:wire")

	_, err := client.CreateMission(context.Background(), &componentpb.CreateMissionRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Empty(t, mgr.originated)
}
