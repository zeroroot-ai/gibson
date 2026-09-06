// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeCMMStore is an in-memory MissionStore for the component mission manager
// tests. The production store is RedisJSON-backed (JSON.SET/GET), which has no
// in-process server, so the manager takes a storeFactory seam and these tests
// inject this fake. Unstubbed interface methods panic (embedded interface).
type fakeCMMStore struct {
	mission.MissionStore
	byID    map[string]*mission.Mission
	list    []*mission.Mission
	saveErr error
	getErr  error
	listErr error
}

func (f *fakeCMMStore) Get(_ context.Context, id types.ID) (*mission.Mission, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	m, ok := f.byID[id.String()]
	if !ok {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return m, nil
}

func (f *fakeCMMStore) Save(_ context.Context, m *mission.Mission) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	if f.byID == nil {
		f.byID = map[string]*mission.Mission{}
	}
	f.byID[m.ID.String()] = m
	return nil
}

func (f *fakeCMMStore) List(_ context.Context, _ *mission.MissionFilter) ([]*mission.Mission, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.list, nil
}

// fakeCMMLedger is an in-memory ReservationLedger: it always grants the request
// and records releases, which is all the origination happy path needs.
type fakeCMMLedger struct {
	released [][2]string
}

func (f *fakeCMMLedger) Reserve(_ context.Context, _ *mission.Mission, _ types.ID, requested mission.ChildBudget) (mission.ChildBudget, error) {
	return requested, nil
}

func (f *fakeCMMLedger) Release(_ context.Context, parentID, childID types.ID) error {
	f.released = append(f.released, [2]string{parentID.String(), childID.String()})
	return nil
}

func (f *fakeCMMLedger) Reserved(_ context.Context, _ types.ID) (mission.ChildBudget, error) {
	return mission.ChildBudget{}, nil
}

// fakeCMMRunStore is an in-memory MissionRunStore for GetMissionRunHistory.
type fakeCMMRunStore struct {
	mission.MissionRunStore
	runs    []*mission.MissionRun
	listErr error
}

func (f *fakeCMMRunStore) ListByMission(_ context.Context, _ types.ID) ([]*mission.MissionRun, error) {
	return f.runs, f.listErr
}

// newCMMTest builds a componentMissionManager whose pool yields a (Redis-less)
// Conn and whose storeFactory returns the injected fakes.
func newCMMTest(t *testing.T, store mission.MissionStore, ledger mission.ReservationLedger) *componentMissionManager {
	t.Helper()
	d := &daemonImpl{logger: testObsLogger(), pool: &mockPool{conn: minimalConn()}}
	return &componentMissionManager{
		daemon: d,
		storeFactory: func(*datapool.Conn) (mission.MissionStore, mission.ReservationLedger) {
			return store, ledger
		},
		runStoreFactory: func(*datapool.Conn) mission.MissionRunStore {
			return &fakeCMMRunStore{}
		},
	}
}

func cmmCtx() context.Context {
	return auth.ContextWithTenantString(context.Background(), "acme")
}

// ---- pure helpers ---------------------------------------------------------

func TestParseTargetIDs(t *testing.T) {
	got, err := parseTargetIDs("")
	require.NoError(t, err)
	require.Nil(t, got, "empty target is a valid empty set")

	id := types.NewID()
	got, err = parseTargetIDs(id.String())
	require.NoError(t, err)
	require.Len(t, got, 1)

	_, err = parseTargetIDs("not-a-uuid")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestOriginationStatus(t *testing.T) {
	cases := []struct {
		err  error
		want codes.Code
	}{
		{mission.ErrNoParentMission, codes.FailedPrecondition},
		{mission.ErrScopeWiden, codes.PermissionDenied},
		{mission.ErrDepthExceeded, codes.FailedPrecondition},
		{mission.ErrLineageSupplied, codes.InvalidArgument},
		{mission.ErrMissingAttribution, codes.Unauthenticated},
		{status.Error(codes.Unknown, "envelope exhausted"), codes.ResourceExhausted},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, status.Code(originationStatus(tc.err)), "for %v", tc.err)
	}
}

// ---- OriginateMission -----------------------------------------------------

func TestOriginateMission_NoParentRefused(t *testing.T) {
	mgr := newCMMTest(t, &fakeCMMStore{}, &fakeCMMLedger{})
	_, err := mgr.OriginateMission(cmmCtx(), component.OriginateMissionRequest{})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "no parent work item must be refused")
}

func TestOriginateMission_ParentNotFound(t *testing.T) {
	mgr := newCMMTest(t, &fakeCMMStore{}, &fakeCMMLedger{})
	_, err := mgr.OriginateMission(cmmCtx(), component.OriginateMissionRequest{ParentMissionID: types.NewID().String()})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestOriginateMission_HappyPath(t *testing.T) {
	parent := &mission.Mission{ID: types.NewID(), TenantID: "acme", Name: "parent"}
	store := &fakeCMMStore{byID: map[string]*mission.Mission{parent.ID.String(): parent}}
	mgr := newCMMTest(t, store, &fakeCMMLedger{})

	body, err := mgr.OriginateMission(cmmCtx(), component.OriginateMissionRequest{
		ParentMissionID: parent.ID.String(),
		ParentWorkID:    "w-1",
		Principal:       "agent:recon",
		GrantID:         "grant-1",
		DefinitionJSON:  []byte(`{"name":"child"}`),
	})
	require.NoError(t, err)
	var rec componentMissionRecord
	require.NoError(t, json.Unmarshal(body, &rec))
	require.NotEmpty(t, rec.ID)
	require.Equal(t, parent.ID.String(), rec.ParentMissionID)
}

// erroringLedger refuses every reservation, driving the origination-refused
// path (originationStatus default → ResourceExhausted).
type erroringLedger struct{ fakeCMMLedger }

func (erroringLedger) Reserve(_ context.Context, _ *mission.Mission, _ types.ID, _ mission.ChildBudget) (mission.ChildBudget, error) {
	return mission.ChildBudget{}, status.Error(codes.Unknown, "parent envelope exhausted")
}

func TestOriginateMission_ReservationRefused(t *testing.T) {
	parent := &mission.Mission{ID: types.NewID(), TenantID: "acme", Name: "parent"}
	store := &fakeCMMStore{byID: map[string]*mission.Mission{parent.ID.String(): parent}}
	mgr := newCMMTest(t, store, &erroringLedger{})

	_, err := mgr.OriginateMission(cmmCtx(), component.OriginateMissionRequest{
		ParentMissionID: parent.ID.String(),
		ParentWorkID:    "w-1",
		Principal:       "agent:recon",
		GrantID:         "grant-1",
		DefinitionJSON:  []byte(`{"name":"child"}`),
	})
	require.Equal(t, codes.ResourceExhausted, status.Code(err), "an exhausted parent envelope backs the caller off")
}

func TestOriginateMission_BadTargetID(t *testing.T) {
	parent := &mission.Mission{ID: types.NewID(), TenantID: "acme"}
	store := &fakeCMMStore{byID: map[string]*mission.Mission{parent.ID.String(): parent}}
	mgr := newCMMTest(t, store, &fakeCMMLedger{})

	_, err := mgr.OriginateMission(cmmCtx(), component.OriginateMissionRequest{
		ParentMissionID: parent.ID.String(),
		TargetID:        "not-a-uuid",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---- oneMission / GetMissionStatus / GetMissionResults --------------------

func TestGetMissionStatus_FoundAndNotFound(t *testing.T) {
	m := &mission.Mission{ID: types.NewID(), TenantID: "acme", Name: "m", Status: mission.MissionStatusRunning}
	store := &fakeCMMStore{byID: map[string]*mission.Mission{m.ID.String(): m}}
	mgr := newCMMTest(t, store, &fakeCMMLedger{})

	body, err := mgr.GetMissionStatus(cmmCtx(), "acme", m.ID.String())
	require.NoError(t, err)
	var rec componentMissionRecord
	require.NoError(t, json.Unmarshal(body, &rec))
	require.Equal(t, m.ID.String(), rec.ID)

	// GetMissionResults shares the same path.
	_, err = mgr.GetMissionResults(cmmCtx(), "acme", m.ID.String())
	require.NoError(t, err)

	_, err = mgr.GetMissionStatus(cmmCtx(), "acme", types.NewID().String())
	require.Equal(t, codes.NotFound, status.Code(err))

	_, err = mgr.GetMissionStatus(cmmCtx(), "acme", "not-a-uuid")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetMissionStatus_TenantMismatchRefused(t *testing.T) {
	mgr := newCMMTest(t, &fakeCMMStore{}, &fakeCMMLedger{})
	// ctx tenant is acme; the argument says evil — the context wins, request fails.
	_, err := mgr.GetMissionStatus(cmmCtx(), "evil", types.NewID().String())
	require.Equal(t, codes.Internal, status.Code(err))
}

// ---- WaitForMission -------------------------------------------------------

func TestWaitForMission_TerminalReturnsImmediately(t *testing.T) {
	m := &mission.Mission{ID: types.NewID(), TenantID: "acme", Status: mission.MissionStatusCompleted}
	store := &fakeCMMStore{byID: map[string]*mission.Mission{m.ID.String(): m}}
	mgr := newCMMTest(t, store, &fakeCMMLedger{})

	body, err := mgr.WaitForMission(cmmCtx(), "acme", m.ID.String(), 0)
	require.NoError(t, err)
	var rec componentMissionRecord
	require.NoError(t, json.Unmarshal(body, &rec))
	require.Equal(t, m.ID.String(), rec.ID)
}

func TestWaitForMission_TimeoutWhileRunning(t *testing.T) {
	m := &mission.Mission{ID: types.NewID(), TenantID: "acme", Status: mission.MissionStatusRunning}
	store := &fakeCMMStore{byID: map[string]*mission.Mission{m.ID.String(): m}}
	mgr := newCMMTest(t, store, &fakeCMMLedger{})

	_, err := mgr.WaitForMission(cmmCtx(), "acme", m.ID.String(), 1) // 1ms → deadline
	require.Equal(t, codes.DeadlineExceeded, status.Code(err))
}

func TestWaitForMission_NotFound(t *testing.T) {
	mgr := newCMMTest(t, &fakeCMMStore{}, &fakeCMMLedger{})
	_, err := mgr.WaitForMission(cmmCtx(), "acme", types.NewID().String(), 0)
	require.Equal(t, codes.NotFound, status.Code(err))
}

// ---- ListMissions ---------------------------------------------------------

func TestListMissions_ProjectsRecords(t *testing.T) {
	a := &mission.Mission{ID: types.NewID(), TenantID: "acme", Name: "a", Status: mission.MissionStatusRunning}
	b := &mission.Mission{ID: types.NewID(), TenantID: "acme", Name: "b", Status: mission.MissionStatusCompleted}
	store := &fakeCMMStore{list: []*mission.Mission{a, b}}
	mgr := newCMMTest(t, store, &fakeCMMLedger{})

	body, err := mgr.ListMissions(cmmCtx(), "acme", nil)
	require.NoError(t, err)
	var recs []componentMissionRecord
	require.NoError(t, json.Unmarshal(body, &recs))
	require.Len(t, recs, 2)
}

func TestListMissions_BadFilter(t *testing.T) {
	mgr := newCMMTest(t, &fakeCMMStore{}, &fakeCMMLedger{})
	_, err := mgr.ListMissions(cmmCtx(), "acme", []byte("not json"))
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---- GetMissionRunHistory -------------------------------------------------

func TestGetMissionRunHistory_ProjectsRuns(t *testing.T) {
	mid := types.NewID()
	runs := []*mission.MissionRun{
		{ID: types.NewID(), MissionID: mid, RunNumber: 1, Status: mission.MissionRunStatusCompleted},
		{ID: types.NewID(), MissionID: mid, RunNumber: 2, Status: mission.MissionRunStatusRunning},
	}
	mgr := newCMMTest(t, &fakeCMMStore{}, &fakeCMMLedger{})
	mgr.runStoreFactory = func(*datapool.Conn) mission.MissionRunStore {
		return &fakeCMMRunStore{runs: runs}
	}

	body, err := mgr.GetMissionRunHistory(cmmCtx(), "acme", mid.String())
	require.NoError(t, err)
	var recs []componentMissionRunRecord
	require.NoError(t, json.Unmarshal(body, &recs))
	require.Len(t, recs, 2)
	require.Equal(t, 1, recs[0].RunNumber)

	_, err = mgr.GetMissionRunHistory(cmmCtx(), "acme", "not-a-uuid")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---- adapter-backed methods: covered up to the adapter boundary -----------

func TestCancelMission_InvalidID(t *testing.T) {
	mgr := newCMMTest(t, &fakeCMMStore{}, &fakeCMMLedger{})
	err := mgr.CancelMission(cmmCtx(), "acme", "not-a-uuid")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestAdapterMethods_TenantMismatchRefused(t *testing.T) {
	mgr := newCMMTest(t, &fakeCMMStore{}, &fakeCMMLedger{})
	// ctx tenant is acme; the argument says evil — refused before the adapter.
	require.Equal(t, codes.Internal, status.Code(mgr.RunMission(cmmCtx(), "evil", types.NewID().String(), nil)))
	require.Equal(t, codes.Internal, status.Code(mgr.CancelMission(cmmCtx(), "evil", types.NewID().String())))
}

func TestStoreBackedMethods_PoolNotConfigured(t *testing.T) {
	// A manager with a nil pool refuses every store-backed call with Unavailable.
	mgr := &componentMissionManager{daemon: &daemonImpl{logger: testObsLogger()}}
	_, err := mgr.GetMissionStatus(cmmCtx(), "acme", types.NewID().String())
	require.Equal(t, codes.Unavailable, status.Code(err))
	_, err = mgr.GetMissionRunHistory(cmmCtx(), "acme", types.NewID().String())
	require.Equal(t, codes.Unavailable, status.Code(err))
}

// ---- constructor ----------------------------------------------------------

func TestNewComponentMissionManager(t *testing.T) {
	d := &daemonImpl{logger: testObsLogger(), pool: &mockPool{conn: minimalConn()}}
	mgr := newComponentMissionManager(d)
	require.NotNil(t, mgr.storeFactory)
	require.NotNil(t, mgr.runStoreFactory)
	require.NotNil(t, mgr.adapter)

	require.Panics(t, func() { newComponentMissionManager(nil) }, "nil daemon must panic")
}

// ---- record projection ----------------------------------------------------

func TestMissionRecordAndLineage(t *testing.T) {
	parentID := types.NewID()
	m := &mission.Mission{
		ID:              types.NewID(),
		Name:            "child",
		Status:          mission.MissionStatusRunning,
		ParentMissionID: &parentID,
		Metadata: map[string]any{
			mission.LineageOriginatingComponent: "agent:recon",
			mission.LineageCapabilityGrantID:    "grant-1",
		},
	}
	rec := missionRecord(m)
	require.Equal(t, m.ID.String(), rec.ID)
	require.Equal(t, parentID.String(), rec.ParentMissionID)

	lineage := lineageOf(m)
	require.Equal(t, "agent:recon", lineage[mission.LineageOriginatingComponent])
	require.Equal(t, "grant-1", lineage[mission.LineageCapabilityGrantID])

	// nil mission → zero record; no lineage → nil map.
	require.Equal(t, componentMissionRecord{}, missionRecord(nil))
	require.Nil(t, lineageOf(&mission.Mission{}))
}

// TestMissionRecord_MetricsAndConstraints covers the metric/constraint branches.
func TestMissionRecord_MetricsAndConstraints(t *testing.T) {
	m := &mission.Mission{
		ID:          types.NewID(),
		Status:      mission.MissionStatusCompleted,
		Constraints: &missionv1.MissionConstraints{MaxCost: 12.5, MaxTokens: 1000},
		Metrics:     &mission.MissionMetrics{TotalCost: 3.25, TotalTokens: 400},
	}
	rec := missionRecord(m)
	require.InDelta(t, 12.5, rec.MaxCostUSD, 0.001)
	require.Equal(t, int64(1000), rec.MaxTokens)
	require.InDelta(t, 3.25, rec.TotalCostUSD, 0.001)
	require.Equal(t, int64(400), rec.TotalTokens)
}
