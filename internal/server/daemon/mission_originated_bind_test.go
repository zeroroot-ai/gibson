// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	goredis "github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// childWithPlaceholder is a stored mission whose definition still carries a
// {{target.*}} placeholder — exactly what Originator.buildChild writes, since the
// originator holds no target store and binds nothing.
func childWithPlaceholder(t *testing.T, targetID types.ID) *mission.Mission {
	t.Helper()
	def := &missionpb.MissionDefinition{
		Id:   "child",
		Name: "child-scan",
		Nodes: map[string]*missionpb.MissionNode{
			"scan": {
				Id:   "scan",
				Type: missionpb.NodeType_NODE_TYPE_TOOL,
				Config: &missionpb.MissionNode_ToolConfig{ToolConfig: &missionpb.ToolNodeConfig{
					ToolName: "nmap",
					Input:    map[string]string{"target": "{{target.host}}"},
				}},
			},
		},
	}
	defJSON, err := mission.MarshalDefinitionJSON(def)
	if err != nil {
		t.Fatalf("marshal definition: %v", err)
	}
	return &mission.Mission{
		ID:                    types.NewID(),
		TenantID:              "tenant-a",
		Name:                  "child-scan",
		MissionDefinitionID:   types.NewID(),
		Status:                mission.MissionStatusPending,
		TargetID:              targetID,
		MissionDefinitionJSON: string(defJSON),
	}
}

// bindTestManager returns a manager whose only wired dependency is a target store
// that answers for one target.
func bindTestManager(id types.ID, target *types.Target) *missionManager {
	return &missionManager{
		logger: slog.New(slog.DiscardHandler),
		targetStore: &fakeTargetStore{get: func(_ context.Context, got types.ID) (*types.Target, error) {
			if got != id {
				return nil, errTargetNotFoundForTest
			}
			return target, nil
		}},
	}
}

// A child mission carrying a placeholder binds against its own target. Before
// this the originate path never bound anything, and the projection backstop
// refused the child rather than dispatching it against the literal text
// "{{target.host}}" (gibson#529).
func TestBindStoredDefinition_ChildBindsAgainstItsOwnTarget(t *testing.T) {
	childTarget := types.NewID()
	rec := childWithPlaceholder(t, childTarget)
	m := bindTestManager(childTarget, &types.Target{
		ID:       childTarget,
		TenantID: "tenant-a",
		Name:     "child-host",
		Type:     "kubernetes",
		URL:      "https://10.60.0.99:6443",
	})

	def, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}

	in := def.GetNodes()["scan"].GetToolConfig().GetInput()["target"]
	if strings.Contains(in, "{{target.") {
		t.Fatalf("the placeholder survived binding: %q", in)
	}
	if !strings.Contains(in, "10.60.0.99") {
		t.Errorf("bound input = %q, want the child's own host", in)
	}
}

// The parent's target is never used. A child narrowed to a different target in the
// parent's set has to reach its own host, and a child dispatched against the
// parent's would assess the wrong one and report the result as the child's.
func TestBindStoredDefinition_TheParentsTargetIsNotReused(t *testing.T) {
	parentTarget := types.NewID()
	childTarget := types.NewID()
	rec := childWithPlaceholder(t, childTarget)

	// The store answers for BOTH, so nothing but the mission's own TargetID can
	// decide which one is bound.
	m := &missionManager{
		logger: slog.New(slog.DiscardHandler),
		targetStore: &fakeTargetStore{get: func(_ context.Context, got types.ID) (*types.Target, error) {
			switch got {
			case parentTarget:
				return &types.Target{ID: parentTarget, TenantID: "tenant-a", Name: "parent-host", URL: "https://10.60.0.1:6443"}, nil
			case childTarget:
				return &types.Target{ID: childTarget, TenantID: "tenant-a", Name: "child-host", URL: "https://10.60.0.2:6443"}, nil
			}
			return nil, errTargetNotFoundForTest
		}},
	}

	def, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	in := def.GetNodes()["scan"].GetToolConfig().GetInput()["target"]
	if strings.Contains(in, "10.60.0.1") {
		t.Errorf("the child bound to the PARENT's host: %q", in)
	}
	if !strings.Contains(in, "10.60.0.2") {
		t.Errorf("bound input = %q, want the child's host 10.60.0.2", in)
	}
}

// The bound definition is written back onto the record, so the stored run, the
// projection and the dispatcher all read one bound copy — the same rule the
// submit path follows.
func TestBindStoredDefinition_WritesTheBoundCopyBackOntoTheRecord(t *testing.T) {
	childTarget := types.NewID()
	rec := childWithPlaceholder(t, childTarget)
	before := rec.MissionDefinitionJSON
	m := bindTestManager(childTarget, &types.Target{
		ID: childTarget, TenantID: "tenant-a", Name: "child-host", URL: "https://10.60.0.7:6443",
	})

	if _, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if rec.MissionDefinitionJSON == before {
		t.Fatal("the record still holds the unbound definition; a later reader would bind it again or not at all")
	}
	if strings.Contains(rec.MissionDefinitionJSON, "{{target.") {
		t.Errorf("the stored definition still carries a placeholder: %s", rec.MissionDefinitionJSON)
	}
	if got := rec.Metadata["target_ref"]; got != "https://10.60.0.7:6443" {
		t.Errorf("target_ref = %v, want the child's own reference", got)
	}
}

// A mission with no target is refused by name rather than bound against nothing.
// Binding against a nil target is what produced "{{target.host}}" as a hostname.
func TestBindStoredDefinition_RefusesAMissionWithNoTarget(t *testing.T) {
	rec := childWithPlaceholder(t, types.NewID())
	rec.TargetID = ""
	m := bindTestManager(types.NewID(), &types.Target{})

	_, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec)
	if err == nil {
		t.Fatal("want a refusal for a mission that names no target")
	}
	if !strings.Contains(err.Error(), "names no target") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// A mission with no definition is refused. It used to reach missionManager.Run
// through a temp file and fail there with "mission definition not found", naming
// a temp path instead of the mission.
func TestBindStoredDefinition_RefusesAMissionWithNoDefinition(t *testing.T) {
	rec := childWithPlaceholder(t, types.NewID())
	rec.MissionDefinitionJSON = ""
	m := bindTestManager(rec.TargetID, &types.Target{ID: rec.TargetID, TenantID: "tenant-a"})

	_, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec)
	if err == nil {
		t.Fatal("want a refusal for a mission with no definition")
	}
	if !strings.Contains(err.Error(), "has no definition") {
		t.Errorf("the refusal does not name the cause: %v", err)
	}
}

// A target the tenant does not own is refused. A stored TargetID is not a licence
// to read a target — the resolution goes through the same ownership check the
// submit path uses.
func TestBindStoredDefinition_RefusesATargetTheTenantDoesNotOwn(t *testing.T) {
	childTarget := types.NewID()
	rec := childWithPlaceholder(t, childTarget)
	m := bindTestManager(childTarget, &types.Target{
		ID: childTarget, TenantID: "someone-else", Name: "not-ours", URL: "https://10.0.0.1:6443",
	})

	_, err := m.bindStoredDefinition(tenantCtx(t, "tenant-a"), rec)
	if err == nil {
		t.Fatal("want a refusal when the mission's target belongs to another tenant")
	}
	// The refusal must be about ownership. A test that accepts any error would
	// pass on a nil store or a typo in the fixture and prove nothing.
	if !strings.Contains(err.Error(), "resolve target") {
		t.Errorf("the refusal is not the ownership check: %v", err)
	}
	t.Logf("ownership refusal: %v", err)
}

// The projection backstop stays. It is the thing that made the unbound-child gap
// visible instead of silent, and it is the guard that catches the next path that
// forgets to bind.
func TestProjection_BackstopStillRefusesAnUnboundNode(t *testing.T) {
	_, _, _, err := nodeKindTargetInput(&missionpb.MissionNode{
		Id:   "scan",
		Type: missionpb.NodeType_NODE_TYPE_TOOL,
		Config: &missionpb.MissionNode_ToolConfig{ToolConfig: &missionpb.ToolNodeConfig{
			ToolName: "nmap",
			Input:    map[string]string{"target": "{{target.host}}"},
		}},
	})
	if err == nil {
		t.Fatal("the backstop accepted a node that was never bound")
	}
	if !strings.Contains(err.Error(), "never bound") {
		t.Errorf("the refusal does not say the node was unbound: %v", err)
	}
}

// runExistingPool is a datapool.Pool whose Conn carries the test Redis client,
// which is all RunExisting needs: missionStoreFor builds a
// ConnBoundMissionStore from Conn.Redis and nothing else.
type runExistingPool struct {
	rdb *goredis.Client
	err error
}

func (p *runExistingPool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &datapool.Conn{Tenant: tenant, Redis: p.rdb}, nil
}

func (p *runExistingPool) Admin(_ context.Context) (*datapool.AdminConn, error) {
	return nil, errTargetNotFoundForTest
}

func (p *runExistingPool) SetAdminPool(_ datapool.AdminAcquirer) {}

func (p *runExistingPool) Close() error { return nil }

var _ datapool.Pool = (*runExistingPool)(nil)

// requireRedisStack returns a client for a Redis with the RedisJSON module, which
// ConnBoundMissionStore needs: it stores a mission with JSON.SET, so miniredis
// cannot stand in for it.
//
// Bounded skip, the shape internal/engine/state already uses. Outside the lane
// that promises a Redis Stack an absent one is a legitimate skip; inside it
// (GIBSON_TEST_REQUIRE_REDIS set, which the coverage job sets against its
// redis/redis-stack-server service) an unreachable or module-less Redis is a
// FAILURE. A probe that can only skip is a test that quietly stops running.
func requireRedisStack(t *testing.T) *goredis.Client {
	t.Helper()
	required := os.Getenv("GIBSON_TEST_REQUIRE_REDIS") != ""
	if testing.Short() && !required {
		t.Skip("skipping Redis-backed test in short mode")
	}

	addr := "localhost:6379"
	if url := os.Getenv("GIBSON_TEST_REDIS_URL"); url != "" {
		addr = strings.TrimPrefix(strings.TrimPrefix(url, "redis://"), "rediss://")
	}
	rdb := goredis.NewClient(&goredis.Options{Addr: addr, DB: 15})

	// JSON.SET is the command the store actually uses, so probe that rather than
	// PING: a plain redis image answers PING and then fails every write.
	probe := "gibson:test:probe:" + types.NewID().String()
	err := rdb.Do(context.Background(), "JSON.SET", probe, "$", `{"ok":true}`).Err()
	if err != nil {
		_ = rdb.Close()
		if required {
			t.Fatalf("GIBSON_TEST_REQUIRE_REDIS is set, so this lane promises a Redis Stack at %s, "+
				"but JSON.SET is unusable: %v (ConnBoundMissionStore needs the RedisJSON module — "+
				"a plain redis image is not enough)", addr, err)
		}
		t.Skipf("Redis Stack not available at %s: %v", addr, err)
	}
	_ = rdb.Del(context.Background(), probe).Err()

	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// runExistingManager returns a manager backed by a real Redis Stack, with the
// given mission already stored, and a target store that answers for target.
func runExistingManager(t *testing.T, rec *mission.Mission, target *types.Target) *missionManager {
	t.Helper()
	rdb := requireRedisStack(t)

	m := &missionManager{
		logger:         slog.New(slog.DiscardHandler),
		pool:           &runExistingPool{rdb: rdb},
		activeMissions: make(map[auth.TenantID]map[string]*activeMission),
		targetStore: &fakeTargetStore{get: func(_ context.Context, got types.ID) (*types.Target, error) {
			if target != nil && got == target.ID {
				return target, nil
			}
			return nil, errTargetNotFoundForTest
		}},
	}
	if rec != nil {
		if err := mission.NewConnBoundMissionStore(rdb).Save(context.Background(), rec); err != nil {
			t.Fatalf("seed mission: %v", err)
		}
		// The keys are uuid-scoped, so this removes only what this test wrote.
		t.Cleanup(func() {
			_ = rdb.Del(context.Background(), "gibson:mission:"+rec.ID.String()).Err()
		})
	}
	return m
}

// RunExisting refuses an id that is not a UUID, naming it. The adapter used to
// hand missionManager.Run a temp-file PATH where a definition id belongs, and the
// failure named the path rather than the mission (gibson#529).
func TestRunExisting_RefusesAnIDThatIsNotAUUID(t *testing.T) {
	m := runExistingManager(t, nil, nil)
	_, err := m.RunExisting(tenantCtx(t, "tenant-a"), "/tmp/gibson-sub-mission-123.yaml")
	if err == nil {
		t.Fatal("want a refusal for an id that is not a mission id")
	}
	if !strings.Contains(err.Error(), "invalid mission id") {
		t.Errorf("the refusal does not say the id is invalid: %v", err)
	}
}

// A tenant-less context is refused before any store is touched, like every other
// missionManager entry point.
func TestRunExisting_RefusesATenantlessContext(t *testing.T) {
	m := runExistingManager(t, nil, nil)
	if _, err := m.RunExisting(context.Background(), types.NewID().String()); err == nil {
		t.Fatal("want a refusal for a request with no tenant")
	}
}

// A mission the store does not hold is refused, naming the mission.
func TestRunExisting_RefusesAMissionTheStoreDoesNotHold(t *testing.T) {
	m := runExistingManager(t, nil, nil)
	_, err := m.RunExisting(tenantCtx(t, "tenant-a"), types.NewID().String())
	if err == nil {
		t.Fatal("want a refusal for a mission that does not exist")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("the refusal does not say the mission is missing: %v", err)
	}
}

// A stored mission with no definition is refused by name, rather than reaching a
// definition lookup that would fail describing something else.
func TestRunExisting_RefusesAStoredMissionWithNoDefinition(t *testing.T) {
	rec := childWithPlaceholder(t, types.NewID())
	rec.MissionDefinitionJSON = ""
	m := runExistingManager(t, rec, &types.Target{ID: rec.TargetID, TenantID: "tenant-a"})

	_, err := m.RunExisting(tenantCtx(t, "tenant-a"), rec.ID.String())
	if err == nil {
		t.Fatal("want a refusal for a stored mission with no definition")
	}
	if !strings.Contains(err.Error(), "has no definition") {
		t.Errorf("the refusal does not name the cause: %v", err)
	}
}

// The binding failure propagates from RunExisting rather than being swallowed and
// left for the projection backstop to catch at dispatch time.
func TestRunExisting_PropagatesABindingFailure(t *testing.T) {
	rec := childWithPlaceholder(t, types.NewID())
	// The target store answers for nothing, so the mission's target will not
	// resolve.
	m := runExistingManager(t, rec, nil)

	_, err := m.RunExisting(tenantCtx(t, "tenant-a"), rec.ID.String())
	if err == nil {
		t.Fatal("want the binding failure to reach the caller")
	}
	if !strings.Contains(err.Error(), "resolve target") {
		t.Errorf("the error is not the binding failure: %v", err)
	}
}

// A mission already running is refused rather than started twice. Two active
// entries for one mission id would have the second overwrite the first, and the
// first's cancel func would be dropped.
func TestRunExisting_RefusesAMissionAlreadyRunning(t *testing.T) {
	rec := childWithPlaceholder(t, types.NewID())
	m := runExistingManager(t, rec, &types.Target{
		ID: rec.TargetID, TenantID: "tenant-a", Name: "h", URL: "https://10.0.0.1:6443",
	})
	tenant, tErr := auth.NewTenantID("tenant-a")
	if tErr != nil {
		t.Fatalf("tenant id: %v", tErr)
	}
	m.setActive(tenant, rec.ID.String(), &activeMission{mission: rec, tenantID: tenant})

	_, err := m.RunExisting(tenantCtx(t, "tenant-a"), rec.ID.String())
	if err == nil {
		t.Fatal("want a refusal for a mission that is already running")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	// The bound definition is still persisted: binding happens before the
	// already-running check, so a reader does not see a half-bound record.
	stored, getErr := mission.NewConnBoundMissionStore(m.pool.(*runExistingPool).rdb).Get(context.Background(), rec.ID)
	if getErr != nil {
		t.Fatalf("read back: %v", getErr)
	}
	if strings.Contains(stored.MissionDefinitionJSON, "{{target.") {
		t.Error("the stored definition still carries a placeholder")
	}
}
