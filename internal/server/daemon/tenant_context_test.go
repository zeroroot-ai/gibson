// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// tenant_context_test.go pins the fail-closed contract established by
// gibson#1232: a tenant-scoped daemon operation reached with no tenant on its
// context is REFUSED. It is never silently widened to auth.SystemTenant, which
// is what the removed tenantFromCtxOrSystem helper did.
//
// Two things are asserted at every call site, not one:
//
//  1. the call returns an error, and
//  2. the per-tenant pool is never consulted.
//
// (2) is the part that actually matters. A test that only checked (1) would
// still pass if the tenant defaulted to auth.SystemTenant and the operation
// then failed for some unrelated downstream reason — the escalation is the
// choice of data plane, so proving the pool was never asked for a tenant is
// what proves the escalation is gone.

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// recordingPool records every tenant the code under test asks it for. Any
// recorded call from a tenant-less request is a defect: the request should
// have been refused before a data plane was selected.
type recordingPool struct {
	asked []string
}

func (p *recordingPool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	p.asked = append(p.asked, tenant.String())
	return nil, errPoolNotWiredInTest
}

func (p *recordingPool) Admin(_ context.Context) (*datapool.AdminConn, error) {
	return nil, errPoolNotWiredInTest
}

func (p *recordingPool) SetAdminPool(_ datapool.AdminAcquirer) {}

func (p *recordingPool) Close() error { return nil }

var _ datapool.Pool = (*recordingPool)(nil)

var errPoolNotWiredInTest = status.Error(codes.Unavailable, "recordingPool: no backing store in test")

func testSlogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testObsLogger() *observability.Logger {
	return observability.NewLogger(observability.Config{
		Component: "tenant-context-test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})
}

// tenantlessContexts enumerates every shape a request can take that carries no
// usable tenant. Both must be refused: auth.TenantFromContext reports ok=false
// for a context with no Identity at all AND for an Identity whose Tenant is the
// zero value (which is exactly what looseIdentityFromMD and the SPIFFE
// direct-dial bypass construct).
func tenantlessContexts() map[string]context.Context {
	return map[string]context.Context{
		"no identity at all": context.Background(),
		"identity, but no tenant": auth.WithIdentity(context.Background(), auth.Identity{
			Subject: "someone@example.test",
		}),
	}
}

func assertRefused(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: tenant-less call was SERVED; want refusal", label)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("%s: refusal is not a gRPC status error: %v", label, err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("%s: refusal code = %s, want FailedPrecondition (message: %s)",
			label, st.Code(), st.Message())
	}
}

func assertPoolUntouched(t *testing.T, p *recordingPool, label string) {
	t.Helper()
	if len(p.asked) != 0 {
		t.Fatalf("%s: a data plane was selected for a tenant-less request: pool asked for %v "+
			"(a default — e.g. auth.SystemTenant — leaked through)", label, p.asked)
	}
}

// --- the helper itself -------------------------------------------------------

func TestTenantFromCtx_AbsentTenantIsRefusedNotDefaulted(t *testing.T) {
	for name, ctx := range tenantlessContexts() {
		t.Run(name, func(t *testing.T) {
			got, err := tenantFromCtx(ctx)
			assertRefused(t, err, "tenantFromCtx")
			if !got.IsZero() {
				t.Fatalf("tenantFromCtx returned tenant %q alongside its error; want the zero TenantID", got.String())
			}
			if got.String() == auth.SystemTenant.String() {
				t.Fatal("tenantFromCtx defaulted an absent tenant to the system tenant (gibson#1232 regression)")
			}
		})
	}
}

func TestTenantFromCtx_PresentTenantPassesThrough(t *testing.T) {
	tenant, err := auth.NewTenantID("zerocool-lab")
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	got, err := tenantFromCtx(auth.ContextWithTenant(context.Background(), tenant))
	if err != nil {
		t.Fatalf("tenantFromCtx on a tenant-carrying context: %v", err)
	}
	if got.String() != "zerocool-lab" {
		t.Fatalf("tenantFromCtx = %q, want zerocool-lab", got.String())
	}
}

// TestTenantFromCtx_ExplicitSystemTenantStillWorks pins the opt-in privileged
// path. Daemon-internal Go code that genuinely needs the reserved system tenant
// stamps it on the context itself; that stamp is honoured. The difference from
// the removed helper is where the decision lives: at the internal call site
// (greppable via auth.SystemTenant, the SDK's documented audit handle) instead
// of inside the resolver, where it applied to every caller silently.
func TestTenantFromCtx_ExplicitSystemTenantStillWorks(t *testing.T) {
	ctx := auth.ContextWithTenant(context.Background(), auth.SystemTenant)
	got, err := tenantFromCtx(ctx)
	if err != nil {
		t.Fatalf("explicitly-stamped system tenant was refused: %v", err)
	}
	if got.String() != auth.SystemTenant.String() {
		t.Fatalf("tenantFromCtx = %q, want %q", got.String(), auth.SystemTenant.String())
	}
}

// --- missionManager call sites ----------------------------------------------

func TestMissionManager_TenantlessCallsAreRefused(t *testing.T) {
	calls := map[string]func(context.Context, *missionManager) error{
		"Run": func(ctx context.Context, m *missionManager) error {
			_, err := m.Run(ctx, "some-definition", "550e8400-e29b-41d4-a716-446655440000", nil, "")
			return err
		},
		"Pause": func(ctx context.Context, m *missionManager) error {
			return m.Pause(ctx, "mission-1", false)
		},
		"Resume": func(ctx context.Context, m *missionManager) error {
			err := m.Resume(ctx, "mission-1")
			return err
		},
		"Stop": func(ctx context.Context, m *missionManager) error {
			return m.Stop(ctx, "mission-1", false)
		},
		"List": func(ctx context.Context, m *missionManager) error {
			_, _, err := m.List(ctx, false, 10, 0)
			return err
		},
		"Get": func(ctx context.Context, m *missionManager) error {
			_, err := m.Get(ctx, "mission-1")
			return err
		},
	}

	for name, call := range calls {
		for ctxName, ctx := range tenantlessContexts() {
			t.Run(name+"/"+ctxName, func(t *testing.T) {
				pool := &recordingPool{}

				// A real brain Registry, instrumented. List and Get select a
				// per-tenant World rather than a pool Conn, so the Registry is
				// their data plane: an engine created here means a tenant-less
				// request picked one, which is the escalation itself.
				regCtx, cancelReg := context.WithCancel(t.Context())
				defer cancelReg()
				reg := brain.NewRegistry(regCtx)
				engines := 0
				reg.OnEngine(func(*brain.Engine) { engines++ })

				mm := &missionManager{logger: testSlogger(), pool: pool, brainRegistry: reg}

				assertRefused(t, call(ctx, mm), "missionManager."+name)
				assertPoolUntouched(t, pool, "missionManager."+name)
				if engines != 0 {
					t.Fatalf("missionManager.%s: a tenant-less request created %d brain engine(s); "+
						"a tenant default leaked through", name, engines)
				}
			})
		}
	}
}

// --- daemonImpl call sites ---------------------------------------------------

func TestDaemonImpl_TenantlessCallsAreRefused(t *testing.T) {
	calls := map[string]func(context.Context, *daemonImpl) error{
		"StopMission": func(ctx context.Context, d *daemonImpl) error {
			return d.StopMission(ctx, "mission-1", false)
		},
		"GetMissionHistory": func(ctx context.Context, d *daemonImpl) error {
			_, _, err := d.GetMissionHistory(ctx, "some-mission", 10, 0)
			return err
		},
		"ListMissions": func(ctx context.Context, d *daemonImpl) error {
			_, _, err := d.ListMissions(ctx, false, "", "", 10, 0)
			return err
		},
		"ListMissionDefinitions": func(ctx context.Context, d *daemonImpl) error {
			_, _, err := d.ListMissionDefinitions(ctx, 10, 0)
			return err
		},
		"GetMissionDefinition": func(ctx context.Context, d *daemonImpl) error {
			_, err := d.GetMissionDefinition(ctx, "some-definition")
			return err
		},
		"CreateMission": func(ctx context.Context, d *daemonImpl) error {
			_, err := d.CreateMission(ctx, api.CreateMissionData{
				Name:                "m",
				TargetID:            "550e8400-e29b-41d4-a716-446655440000",
				MissionDefinitionID: "550e8400-e29b-41d4-a716-446655440001",
			})
			return err
		},
		"CreateMissionDefinition": func(ctx context.Context, d *daemonImpl) error {
			_, err := d.CreateMissionDefinition(ctx, api.CreateMissionDefinitionData{
				Definition: &missionpb.MissionDefinition{Name: "some-definition"},
			})
			return err
		},
		"UpdateMissionDefinition": func(ctx context.Context, d *daemonImpl) error {
			_, err := d.UpdateMissionDefinition(ctx, api.UpdateMissionDefinitionData{
				Definition: &missionpb.MissionDefinition{Name: "some-definition"},
			})
			return err
		},
	}

	for name, call := range calls {
		for ctxName, ctx := range tenantlessContexts() {
			t.Run(name+"/"+ctxName, func(t *testing.T) {
				pool := &recordingPool{}
				d := &daemonImpl{
					logger: testObsLogger(),
					pool:   pool,
				}
				assertRefused(t, call(ctx, d), "daemonImpl."+name)
				assertPoolUntouched(t, pool, "daemonImpl."+name)
			})
		}
	}
}

// NOTE: TestDaemonImpl_StopMissionRefusesBeforeCancelling used to live here,
// pinning the hoist of the tenant check above a mutation of a daemon-level
// activeMissions map[string]context.CancelFunc. That field was deleted
// (GHSA-hmq9-jvvc-73w9, gibson#1271): it was a mission-ID-keyed cancel map
// with no tenant component, so cancellation now goes solely through
// missionManager, which is keyed by (tenant, missionID). The invariant this
// test pinned — no destructive side effect before the tenant check — is now
// covered by two narrower tests instead of one combined one:
// TestDaemonImpl_TenantlessCallsAreRefused above (StopMission is refused and
// the pool is never touched) and TestMissionManager_TenantlessCallsAreRefused
// (missionManager.Stop itself refuses before calling active.cancel()).
// TestDaemonHasNoMissionIDKeyedCancelMap in daemon_test.go is the structural
// guard against the field's reintroduction.

// --- harness mission adapter -------------------------------------------------

func TestMissionHarnessAdapter_TenantlessStoreLookupIsRefused(t *testing.T) {
	for ctxName, ctx := range tenantlessContexts() {
		t.Run(ctxName, func(t *testing.T) {
			pool := &recordingPool{}
			a := newMissionHarnessAdapter(&daemonImpl{logger: testObsLogger(), pool: pool})

			_, release, err := a.storeForCtx(ctx)
			if release != nil {
				release()
			}
			assertRefused(t, err, "missionHarnessAdapter.storeForCtx")
			assertPoolUntouched(t, pool, "missionHarnessAdapter.storeForCtx")
		})
	}
}
