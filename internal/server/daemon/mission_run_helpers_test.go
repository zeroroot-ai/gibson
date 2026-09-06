// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// ---- fakes (embedded interface: unstubbed methods panic loudly) -----------

type fakeDefStore struct {
	mission.MissionStore
	getDef   func(ctx context.Context, name string) (*missionpb.MissionDefinition, error)
	listDefs func(ctx context.Context) ([]*missionpb.MissionDefinition, error)
	findOrCr func(ctx context.Context, m *mission.Mission) (*mission.Mission, bool, error)
}

func (f *fakeDefStore) GetDefinition(ctx context.Context, name string) (*missionpb.MissionDefinition, error) {
	return f.getDef(ctx, name)
}

func (f *fakeDefStore) ListDefinitions(ctx context.Context) ([]*missionpb.MissionDefinition, error) {
	return f.listDefs(ctx)
}

func (f *fakeDefStore) FindOrCreateByName(ctx context.Context, m *mission.Mission) (*mission.Mission, bool, error) {
	return f.findOrCr(ctx, m)
}

type fakeRunStore struct {
	mission.MissionRunStore
	nextNum func(ctx context.Context, missionID types.ID) (int, error)
	save    func(ctx context.Context, run *mission.MissionRun) error
}

func (f *fakeRunStore) GetNextRunNumber(ctx context.Context, missionID types.ID) (int, error) {
	return f.nextNum(ctx, missionID)
}

func (f *fakeRunStore) Save(ctx context.Context, run *mission.MissionRun) error {
	return f.save(ctx, run)
}

type fakeAuthzStore struct {
	mission.MissionAuthzStore
	completed []string
	cancelled []string
	failWith  error
}

func (f *fakeAuthzStore) MarkCompleted(_ context.Context, runID string) error {
	f.completed = append(f.completed, runID)
	return f.failWith
}

func (f *fakeAuthzStore) MarkCancelled(_ context.Context, runID string) error {
	f.cancelled = append(f.cancelled, runID)
	return f.failWith
}

type fakeTargetStore struct {
	get func(ctx context.Context, id types.ID) (*types.Target, error)
}

func (f *fakeTargetStore) Get(ctx context.Context, id types.ID) (*types.Target, error) {
	return f.get(ctx, id)
}

func helperMM() *missionManager {
	return &missionManager{logger: slog.New(slog.DiscardHandler)}
}

// ---- runTargetRef ---------------------------------------------------------

func TestRunTargetRef(t *testing.T) {
	if got := runTargetRef(&types.Target{Name: "n", URL: "https://u"}); got != "https://u" {
		t.Errorf("URL should win, got %q", got)
	}
	if got := runTargetRef(&types.Target{Name: "n", Connection: map[string]any{"url": "https://c"}}); got != "https://c" {
		t.Errorf("connection url should win over name, got %q", got)
	}
	if got := runTargetRef(&types.Target{Name: "n"}); got != "n" {
		t.Errorf("name is the fallback, got %q", got)
	}
}

// ---- loadRunDefinition ----------------------------------------------------

func TestLoadRunDefinition_ByName(t *testing.T) {
	want := &missionpb.MissionDefinition{Id: "id-1", Name: "recon"}
	st := &fakeDefStore{getDef: func(_ context.Context, name string) (*missionpb.MissionDefinition, error) {
		if name != "recon" {
			t.Errorf("lookup name: got %q", name)
		}
		return want, nil
	}}
	got, err := helperMM().loadRunDefinition(context.Background(), st, "recon")
	if err != nil || got != want {
		t.Fatalf("want definition, got %v err %v", got, err)
	}
}

func TestLoadRunDefinition_StoreError(t *testing.T) {
	st := &fakeDefStore{getDef: func(context.Context, string) (*missionpb.MissionDefinition, error) {
		return nil, errors.New("redis down")
	}}
	_, err := helperMM().loadRunDefinition(context.Background(), st, "recon")
	if err == nil || !strings.Contains(err.Error(), "failed to load mission definition") {
		t.Fatalf("want load error, got %v", err)
	}
}

func TestLoadRunDefinition_FallsBackToIDLookup(t *testing.T) {
	want := &missionpb.MissionDefinition{Id: "id-2", Name: "scan"}
	st := &fakeDefStore{
		getDef: func(context.Context, string) (*missionpb.MissionDefinition, error) { return nil, nil },
		listDefs: func(context.Context) ([]*missionpb.MissionDefinition, error) {
			return []*missionpb.MissionDefinition{{Id: "other"}, want}, nil
		},
	}
	got, err := helperMM().loadRunDefinition(context.Background(), st, "id-2")
	if err != nil || got != want {
		t.Fatalf("want ID-fallback hit, got %v err %v", got, err)
	}
}

func TestLoadRunDefinition_NotFound(t *testing.T) {
	st := &fakeDefStore{
		getDef:   func(context.Context, string) (*missionpb.MissionDefinition, error) { return nil, nil },
		listDefs: func(context.Context) ([]*missionpb.MissionDefinition, error) { return nil, errors.New("nope") },
	}
	_, err := helperMM().loadRunDefinition(context.Background(), st, "ghost")
	if err == nil || !strings.Contains(err.Error(), "mission definition not found") {
		t.Fatalf("want not-found, got %v", err)
	}
}

// ---- findOrCreateRecord ---------------------------------------------------

func TestFindOrCreateRecord_NilStoreUsesTemplate(t *testing.T) {
	tmpl := &mission.Mission{Name: "m"}
	got, err := helperMM().findOrCreateRecord(context.Background(), nil, tmpl, "ref")
	if err != nil || got != tmpl {
		t.Fatalf("nil store must return template, got %v err %v", got, err)
	}
}

func TestFindOrCreateRecord_StoreError(t *testing.T) {
	st := &fakeDefStore{findOrCr: func(context.Context, *mission.Mission) (*mission.Mission, bool, error) {
		return nil, false, errors.New("boom")
	}}
	_, err := helperMM().findOrCreateRecord(context.Background(), st, &mission.Mission{Name: "m"}, "")
	if err == nil || !strings.Contains(err.Error(), "failed to find or create mission") {
		t.Fatalf("want wrapped error, got %v", err)
	}
}

func TestFindOrCreateRecord_ExistingRefreshesMetadata(t *testing.T) {
	existing := &mission.Mission{ID: types.NewID(), Name: "m"} // nil Metadata on purpose
	st := &fakeDefStore{findOrCr: func(context.Context, *mission.Mission) (*mission.Mission, bool, error) {
		return existing, false, nil
	}}
	tmpl := &mission.Mission{Name: "m", Metadata: map[string]any{"variables": map[string]string{"k": "v"}}}
	got, err := helperMM().findOrCreateRecord(context.Background(), st, tmpl, "https://target")
	if err != nil {
		t.Fatal(err)
	}
	if got.Metadata["target_ref"] != "https://target" {
		t.Errorf("target_ref not refreshed: %v", got.Metadata)
	}
	if _, ok := got.Metadata["variables"]; !ok {
		t.Errorf("variables not copied: %v", got.Metadata)
	}
}

func TestFindOrCreateRecord_NewMissionKeepsRecordAsIs(t *testing.T) {
	fresh := &mission.Mission{ID: types.NewID(), Name: "m"}
	st := &fakeDefStore{findOrCr: func(context.Context, *mission.Mission) (*mission.Mission, bool, error) {
		return fresh, true, nil
	}}
	got, err := helperMM().findOrCreateRecord(context.Background(), st, &mission.Mission{Name: "m"}, "ref")
	if err != nil || got != fresh {
		t.Fatalf("want fresh record untouched, got %v err %v", got, err)
	}
	if got.Metadata != nil {
		t.Errorf("new mission must not get metadata refreshed here: %v", got.Metadata)
	}
}

// ---- createRunRecord ------------------------------------------------------

func TestCreateRunRecord_NilStoreEphemeral(t *testing.T) {
	run, err := helperMM().createRunRecord(context.Background(), nil, types.NewID())
	if err != nil || run == nil {
		t.Fatalf("want ephemeral run, got %v err %v", run, err)
	}
	if run.RunNumber != 1 {
		t.Errorf("ephemeral run number: want 1, got %d", run.RunNumber)
	}
}

func TestCreateRunRecord_NextNumberError(t *testing.T) {
	st := &fakeRunStore{nextNum: func(context.Context, types.ID) (int, error) { return 0, errors.New("boom") }}
	_, err := helperMM().createRunRecord(context.Background(), st, types.NewID())
	if err == nil || !strings.Contains(err.Error(), "failed to get next run number") {
		t.Fatalf("want run-number error, got %v", err)
	}
}

func TestCreateRunRecord_SaveError(t *testing.T) {
	st := &fakeRunStore{
		nextNum: func(context.Context, types.ID) (int, error) { return 3, nil },
		save:    func(context.Context, *mission.MissionRun) error { return errors.New("boom") },
	}
	_, err := helperMM().createRunRecord(context.Background(), st, types.NewID())
	if err == nil || !strings.Contains(err.Error(), "failed to save mission run") {
		t.Fatalf("want save error, got %v", err)
	}
}

func TestCreateRunRecord_Persisted(t *testing.T) {
	var saved *mission.MissionRun
	st := &fakeRunStore{
		nextNum: func(context.Context, types.ID) (int, error) { return 7, nil },
		save:    func(_ context.Context, r *mission.MissionRun) error { saved = r; return nil },
	}
	run, err := helperMM().createRunRecord(context.Background(), st, types.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if run.RunNumber != 7 || saved != run {
		t.Fatalf("want saved run number 7, got %+v (saved %v)", run, saved)
	}
}

// ---- findActiveAnyTenant --------------------------------------------------

func TestFindActiveAnyTenant(t *testing.T) {
	mm := helperMM()
	mm.activeMissions = make(map[auth.TenantID]map[string]*activeMission)
	acme := auth.MustNewTenantID("acme")
	want := &activeMission{tenantID: acme}
	mm.setActive(acme, "m-1", want)

	got, ok := mm.findActiveAnyTenant("m-1")
	if !ok || got != want {
		t.Fatalf("want active entry, got %v ok=%v", got, ok)
	}
	if _, ok := mm.findActiveAnyTenant("ghost"); ok {
		t.Error("unknown mission must not be found")
	}
}

// ---- persistTraceID -------------------------------------------------------

func TestPersistTraceID_NoTraceIsNoop(t *testing.T) {
	mi := &mission.Mission{}
	helperMM().persistTraceID(context.Background(), "m-1", mi)
	if mi.Metadata != nil {
		t.Errorf("no trace on ctx must not touch metadata: %v", mi.Metadata)
	}
}

func TestPersistTraceID_StampsTraceID(t *testing.T) {
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0x01},
		SpanID:  trace.SpanID{0x02},
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)
	mi := &mission.Mission{}
	helperMM().persistTraceID(ctx, "m-1", mi)
	if mi.Metadata["trace_id"] != sc.TraceID().String() {
		t.Errorf("trace_id not stamped: %v", mi.Metadata)
	}
}

// ---- resolveRunTargetInfo -------------------------------------------------

func TestResolveRunTargetInfo_SyntheticDiscoveryTarget(t *testing.T) {
	mm := helperMM()
	info, err := mm.resolveRunTargetInfo(context.Background(), "00000000-0000-0000-0000-d15c00e00000")
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != "discovery" {
		t.Errorf("want synthetic discovery target, got %+v", info)
	}
}

func TestResolveRunTargetInfo_NonTargetStoreFallback(t *testing.T) {
	mm := helperMM() // nil targetStore does not satisfy mission.TargetStore
	id := types.NewID()
	info, err := mm.resolveRunTargetInfo(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "mission-target" {
		t.Errorf("want ID-only stub, got %+v", info)
	}
}

func TestResolveRunTargetInfo_GetError(t *testing.T) {
	mm := helperMM()
	mm.targetStore = &fakeTargetStore{get: func(context.Context, types.ID) (*types.Target, error) {
		return nil, errors.New("boom")
	}}
	if _, err := mm.resolveRunTargetInfo(context.Background(), types.NewID()); err == nil {
		t.Fatal("want target-load error")
	}
}

func TestResolveRunTargetInfo_FullTarget(t *testing.T) {
	id := types.NewID()
	mm := helperMM()
	mm.targetStore = &fakeTargetStore{get: func(_ context.Context, gotID types.ID) (*types.Target, error) {
		if gotID != id {
			t.Errorf("lookup ID: got %v", gotID)
		}
		return &types.Target{ID: id, Name: "prod-api", URL: "https://x", Type: "web"}, nil
	}}
	info, err := mm.resolveRunTargetInfo(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "prod-api" {
		t.Errorf("want full target info, got %+v", info)
	}
}

// ---- finalizeAuthzState ---------------------------------------------------

func TestFinalizeAuthzState(t *testing.T) {
	mm := helperMM()
	st := &fakeAuthzStore{}
	mm.authzStore = st

	mm.finalizeAuthzState(context.Background(), nil, mission.MissionStatusCompleted) // nil run: no-op
	if len(st.completed)+len(st.cancelled) != 0 {
		t.Fatal("nil run must not touch the authz store")
	}

	run := mission.NewMissionRun(types.NewID(), 1)
	mm.finalizeAuthzState(context.Background(), run, mission.MissionStatusCompleted)
	if len(st.completed) != 1 || st.completed[0] != run.ID.String() {
		t.Errorf("completed run not marked: %v", st.completed)
	}

	mm.finalizeAuthzState(context.Background(), run, mission.MissionStatusFailed)
	if len(st.cancelled) != 1 {
		t.Errorf("non-completed run must be marked cancelled: %v", st.cancelled)
	}

	// Store errors are logged, never propagated.
	st.failWith = errors.New("redis down")
	mm.finalizeAuthzState(context.Background(), run, mission.MissionStatusCompleted)
	mm.finalizeAuthzState(context.Background(), run, mission.MissionStatusFailed)
}

// ---- span helpers ---------------------------------------------------------

func TestStartMissionSpan_DisabledTracing(t *testing.T) {
	mm := helperMM()
	ctx := context.Background()
	gotCtx, span := mm.startMissionSpan(ctx, "m-1", "recon")
	if span != nil || gotCtx != ctx {
		t.Fatalf("disabled tracing must return (ctx, nil), got span=%v", span)
	}
}

func TestStartMissionSpan_EnabledTracing(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	mm := helperMM()
	mm.otelStack = &observability.OTelObservabilityStack{TracerProvider: tp}

	gotCtx, span := mm.startMissionSpan(context.Background(), "m-1", "recon")
	if span == nil {
		t.Fatal("enabled tracing must return a span")
	}
	span.End()
	if !trace.SpanFromContext(gotCtx).SpanContext().IsValid() {
		t.Error("returned context must carry the started span")
	}
}

func TestRecordMissionOutcomeSpan_NilSpanIsNoop(_ *testing.T) {
	recordMissionOutcomeSpan(nil, mission.MissionStatusCompleted, "", time.Second)
	recordMissionOutcomeSpan(nil, mission.MissionStatusFailed, "boom", time.Second)
}

func TestRecordMissionOutcomeSpan_WithSpan(_ *testing.T) {
	span := trace.SpanFromContext(context.Background()) // noop span, non-nil
	recordMissionOutcomeSpan(span, mission.MissionStatusCompleted, "", time.Second)
	recordMissionOutcomeSpan(span, mission.MissionStatusFailed, "boom", time.Second)
}

// ---- failBeforeStart ------------------------------------------------------

func TestFailBeforeStart_ProjectsStartedThenFailed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm := helperMM()
	mm.brainRegistry = brain.NewRegistry(ctx)
	acme := auth.MustNewTenantID("acme")

	mm.failBeforeStart(acme, "m-preflight", "recon", "pool not configured")

	waitWorldStatus(t, mm.brainRegistry.For(acme.String()), "m-preflight", string(brain.MissionFailed))
}

// ---- executeMission pre-flight failure paths ------------------------------

// execMissionTestManager builds a manager wired with just enough to reach and
// exercise executeMission's pre-flight failure branches (no live cluster).
func execMissionTestManager(ctx context.Context, t *testing.T) (*missionManager, auth.TenantID) {
	t.Helper()
	mm := helperMM()
	mm.brainRegistry = brain.NewRegistry(ctx)
	mm.activeMissions = make(map[auth.TenantID]map[string]*activeMission)
	return mm, auth.MustNewTenantID("acme")
}

func seedRunnableActive(mm *missionManager, tenant auth.TenantID, missionID string) {
	mctx, cancel := context.WithCancel(context.Background())
	mm.setActive(tenant, missionID, &activeMission{
		mission:    &mission.Mission{ID: types.ID(missionID), Name: "recon", TenantID: tenant.String()},
		missionRun: mission.NewMissionRun(types.ID(missionID), 1),
		ctx:        mctx,
		cancel:     cancel,
		startTime:  time.Now(),
		tenantID:   tenant,
	})
}

// waitWorldStatus blocks until the mission's folded World status equals want,
// or fails the test after a short deadline. The World folds submitted brain
// events asynchronously, so callers poll rather than read once.
func waitWorldStatus(t *testing.T, eng *brain.Engine, missionID, want string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for worldMissionStatus(eng, missionID) != want {
		select {
		case <-deadline:
			t.Fatalf("world status for %s: want %q, got %q", missionID, want, worldMissionStatus(eng, missionID))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// assertWorldFailed waits for the mission's folded World status to reach failed,
// which is how a pre-flight failure surfaces (MissionStarted+MissionDone pair).
func assertWorldFailed(t *testing.T, mm *missionManager, tenant auth.TenantID, missionID string) {
	t.Helper()
	waitWorldStatus(t, mm.brainRegistry.For(tenant.String()), missionID, string(brain.MissionFailed))
}

func TestExecuteMission_ActiveNotFound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm, _ := execMissionTestManager(ctx, t)
	// No active entry registered: internal invariant failure, logged only.
	mm.executeMission(context.Background(), "ghost", &missionpb.MissionDefinition{Name: "recon"})
}

func TestExecuteMission_PoolNil_FailsBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm, tenant := execMissionTestManager(ctx, t)
	mm.pool = nil
	seedRunnableActive(mm, tenant, "m-nopool")

	mm.executeMission(context.Background(), "m-nopool", &missionpb.MissionDefinition{Name: "recon"})
	assertWorldFailed(t, mm, tenant, "m-nopool")
}

func TestExecuteMission_PoolError_FailsBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm, tenant := execMissionTestManager(ctx, t)
	mm.pool = &mockPool{err: errors.New("tenant not provisioned")}
	seedRunnableActive(mm, tenant, "m-poolerr")

	mm.executeMission(context.Background(), "m-poolerr", &missionpb.MissionDefinition{Name: "recon"})
	assertWorldFailed(t, mm, tenant, "m-poolerr")
}

func TestExecuteMission_BootstrapError_FailsBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm, tenant := execMissionTestManager(ctx, t)
	// A Conn with a nil Neo4j session: SessionGraphClient is nil-safe, so
	// mission-graph bootstrap returns a driver-not-connected error rather than
	// panicking — driving executeMission through the bootstrap-failure branch.
	mm.pool = &mockPool{conn: minimalConn()}
	seedRunnableActive(mm, tenant, "m-bootstrap")

	mm.executeMission(context.Background(), "m-bootstrap", &missionpb.MissionDefinition{Name: "recon"})
	assertWorldFailed(t, mm, tenant, "m-bootstrap")
}

// ---- Pause / Resume -------------------------------------------------------

func TestPause_NotRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm, tenant := execMissionTestManager(ctx, t)
	err := mm.Pause(auth.WithTenant(context.Background(), tenant), "ghost", false)
	if err == nil || !strings.Contains(err.Error(), "not found or not running") {
		t.Fatalf("want not-running error, got %v", err)
	}
}

func TestPause_Running(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm, tenant := execMissionTestManager(ctx, t)
	seedRunnableActive(mm, tenant, "m-run")
	if err := mm.Pause(auth.WithTenant(context.Background(), tenant), "m-run", false); err != nil {
		t.Fatalf("pause of a running mission: %v", err)
	}
}

func TestResume_NotActive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm, tenant := execMissionTestManager(ctx, t)
	err := mm.Resume(auth.WithTenant(context.Background(), tenant), "ghost")
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("want not-active error, got %v", err)
	}
}

func TestResume_NotPaused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm, tenant := execMissionTestManager(ctx, t)
	seedRunnableActive(mm, tenant, "m-run")
	// No pause submitted: the World never reaches paused, so resume refuses.
	err := mm.Resume(auth.WithTenant(context.Background(), tenant), "m-run")
	if err == nil || !strings.Contains(err.Error(), "cannot resume") {
		t.Fatalf("want cannot-resume error, got %v", err)
	}
}

func TestResume_Paused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm, tenant := execMissionTestManager(ctx, t)
	seedRunnableActive(mm, tenant, "m-run")

	// A mission can only be paused once it exists in the World: executeMission
	// submits MissionStarted before any pause is possible. Mirror that here.
	eng := mm.brainRegistry.For(tenant.String())
	eng.Submit(brain.MissionStarted{ID: "m-run", Name: "recon"})
	waitWorldStatus(t, eng, "m-run", string(brain.MissionRunning))

	tctx := auth.WithTenant(context.Background(), tenant)
	if err := mm.Pause(tctx, "m-run", false); err != nil {
		t.Fatalf("pause: %v", err)
	}
	// Wait for the World to fold the pause before resuming.
	waitWorldStatus(t, eng, "m-run", string(brain.MissionPaused))
	if err := mm.Resume(tctx, "m-run"); err != nil {
		t.Fatalf("resume of a paused mission: %v", err)
	}
}

// ---- Run pre-flight refusals ---------------------------------------------

func TestRun_PreflightRefusals(t *testing.T) {
	mm := helperMM()
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	if _, err := mm.Run(ctx, "", "t", nil, ""); err == nil || !strings.Contains(err.Error(), "mission_definition_id is required") {
		t.Errorf("empty definition ID: got %v", err)
	}
	if _, err := mm.Run(ctx, "def", "", nil, ""); err == nil || !strings.Contains(err.Error(), "target_id is required") {
		t.Errorf("empty target ID: got %v", err)
	}
	// No tenant on the context: refused, never run as the system tenant.
	if _, err := mm.Run(context.Background(), "def", "t", nil, ""); err == nil {
		t.Error("tenant-less context must be refused")
	}
	// Tenant present but no pool: missionStoreFor yields a nil store.
	if _, err := mm.Run(ctx, "def", "t", nil, ""); err == nil || !strings.Contains(err.Error(), "mission store not initialized") {
		t.Errorf("nil store: got %v", err)
	}
}
