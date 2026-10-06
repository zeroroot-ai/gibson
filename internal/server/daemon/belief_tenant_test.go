// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	worldpb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/world/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// testBeliefModel is a valid belief model artifact with the given version.
func testBeliefModel(version string) []byte {
	return fmt.Appendf(nil, `{
  "version": %q,
  "variables": ["reachable", "exploitable", "juicy"],
  "edges": [["reachable", "exploitable"], ["exploitable", "juicy"]],
  "cpds": {
    "reachable": {"values": [[0.5], [0.5]]},
    "exploitable": {"evidence": ["reachable"], "evidence_card": [2], "values": [[0.9, 0.2], [0.1, 0.8]]},
    "juicy": {"evidence": ["exploitable"], "evidence_card": [2], "values": [[0.9, 0.3], [0.1, 0.7]]}
  }
}`, version)
}

// testEdgePosteriors is a valid edge posterior artifact with the given version.
func testEdgePosteriors(version string) []byte {
	return fmt.Appendf(nil, `{"version":%q,"posteriors":{"RESOLVES_TO":{"alpha":8,"beta":4}}}`, version)
}

// fakeBeliefArtifacts is an in-memory belief artifact store. Each stored
// version of a tenant carries the label "tenant-<tenant>-v<n>", as the real
// store writes it.
type fakeBeliefArtifacts struct {
	mu      sync.Mutex
	current map[string]int64
	stored  map[string]map[int64]bool
	err     error
	// versionErr fails Version only. badModel makes Version return a belief
	// model that does not parse.
	versionErr error
	badModel   bool
}

func newFakeBeliefArtifacts() *fakeBeliefArtifacts {
	return &fakeBeliefArtifacts{current: map[string]int64{}, stored: map[string]map[int64]bool{}}
}

// makeCurrent stores version v of tenant and makes it current.
func (f *fakeBeliefArtifacts) makeCurrent(tenant string, v int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stored[tenant] == nil {
		f.stored[tenant] = map[int64]bool{}
	}
	f.stored[tenant][v] = true
	f.current[tenant] = v
}

func (f *fakeBeliefArtifacts) CurrentVersions(context.Context) (map[string]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]int64, len(f.current))
	for k, v := range f.current {
		out[k] = v
	}
	return out, nil
}

func (f *fakeBeliefArtifacts) Version(_ context.Context, tenant string, v int64) (model, edges []byte, found bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, nil, false, f.err
	}
	if f.versionErr != nil {
		return nil, nil, false, f.versionErr
	}
	if !f.stored[tenant][v] {
		return nil, nil, false, nil
	}
	label := fmt.Sprintf("tenant-%s-v%d", tenant, v)
	if f.badModel {
		return []byte(`{"version":"broken"}`), testEdgePosteriors(label), true, nil
	}
	return testBeliefModel(label), testEdgePosteriors(label), true, nil
}

// testTenantBeliefs builds a tenantBeliefs over store. A nil store is an
// empty store: every tenant uses the embedded default.
func testTenantBeliefs(t *testing.T, schema *ontology.BeliefSchemaRegistry, store *fakeBeliefArtifacts) *tenantBeliefs {
	t.Helper()
	if store == nil {
		store = newFakeBeliefArtifacts()
	}
	b, err := newTenantBeliefs(store, schema, nil)
	if err != nil {
		t.Fatalf("newTenantBeliefs: %v", err)
	}
	return b
}

func testSchema(t *testing.T) *ontology.BeliefSchemaRegistry {
	t.Helper()
	reg, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	return reg
}

func mustPin(t *testing.T, b *tenantBeliefs, tenant string) (label string, release func()) {
	t.Helper()
	label, release, err := b.Pin(context.Background(), tenant)
	if err != nil {
		t.Fatalf("Pin(%s): %v", tenant, err)
	}
	return label, release
}

// A tenant with a current version gets its artifact. A second tenant with
// none gets the embedded default. The engine providers of each tenant report
// the version of that tenant.
func TestTenantBeliefs_EachTenantGetsItsOwnVersion(t *testing.T) {
	store := newFakeBeliefArtifacts()
	store.makeCurrent("acme", 2)
	b := testTenantBeliefs(t, testSchema(t), store)

	acme, releaseAcme := mustPin(t, b, "acme")
	defer releaseAcme()
	globex, releaseGlobex := mustPin(t, b, "globex")
	defer releaseGlobex()

	if acme != "tenant-acme-v2" {
		t.Errorf("acme pinned %q, want tenant-acme-v2", acme)
	}
	if globex != "base-v1" {
		t.Errorf("globex pinned %q, want the default base-v1", globex)
	}
	acmeTB := b.forTenant("acme")
	if got := (tenantBeliefProvider{acmeTB}).Version(); got != "tenant-acme-v2" {
		t.Errorf("acme engine belief version = %q, want tenant-acme-v2", got)
	}
	if got, want := (tenantSliceBeliefProvider{acmeTB}).Version(), "native-slice-v0-uninformative-prior+edges:tenant-acme-v2"; got != want {
		t.Errorf("acme engine slice version = %q, want %q", got, want)
	}
	if got := (tenantEdgePosteriors{acmeTB}).Posterior("RESOLVES_TO").Mean(); got != 8.0/12.0 {
		t.Errorf("acme engine RESOLVES_TO mean = %v, want %v", got, 8.0/12.0)
	}
	prior := brain.UninformativeEdgePosteriors{}.Posterior("")
	if got := (tenantEdgePosteriors{acmeTB}).InNodeStrength("Host", "exploitable", "reachable"); got != prior {
		t.Errorf("acme engine unfitted in-node strength = %+v, want the prior %+v", got, prior)
	}
	if got := (tenantEdgePosteriors{acmeTB}).Leak("Host", "exploitable"); got != prior {
		t.Errorf("acme engine unfitted leak = %+v, want the prior %+v", got, prior)
	}
	if got := (tenantBeliefProvider{b.forTenant("globex")}).Version(); got != "base-v1" {
		t.Errorf("globex engine belief version = %q, want base-v1", got)
	}
}

// A version flip waits for the running mission: the in-flight mission keeps
// the version it pinned, and the next mission after it pins the new one.
func TestTenantBeliefs_AnInFlightMissionKeepsItsVersion(t *testing.T) {
	store := newFakeBeliefArtifacts()
	store.makeCurrent("acme", 1)
	b := testTenantBeliefs(t, testSchema(t), store)
	tb := b.forTenant("acme")

	first, releaseFirst := mustPin(t, b, "acme")
	if first != "tenant-acme-v1" {
		t.Fatalf("first mission pinned %q, want tenant-acme-v1", first)
	}

	store.makeCurrent("acme", 2)
	if err := b.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := (tenantBeliefProvider{tb}).Version(); got != "tenant-acme-v1" {
		t.Fatalf("the engine scores with %q while the first mission runs, want tenant-acme-v1", got)
	}

	releaseFirst()
	releaseFirst() // a second call does nothing
	if got := (tenantBeliefProvider{tb}).Version(); got != "tenant-acme-v2" {
		t.Fatalf("the engine scores with %q after the first mission ended, want tenant-acme-v2", got)
	}
	next, releaseNext := mustPin(t, b, "acme")
	defer releaseNext()
	if next != "tenant-acme-v2" {
		t.Fatalf("the next mission pinned %q, want tenant-acme-v2", next)
	}
}

// A tenant with no running mission swaps at the refresh.
func TestTenantBeliefs_AnIdleTenantSwapsAtTheRefresh(t *testing.T) {
	store := newFakeBeliefArtifacts()
	b := testTenantBeliefs(t, testSchema(t), store)
	_, release := mustPin(t, b, "acme")
	release()

	store.makeCurrent("acme", 4)
	if err := b.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := (tenantBeliefProvider{b.forTenant("acme")}).Version(); got != "tenant-acme-v4" {
		t.Fatalf("idle engine scores with %q after the refresh, want tenant-acme-v4", got)
	}
}

// A mission never starts on a version that the daemon could not read.
func TestTenantBeliefs_AReadErrorFailsThePin(t *testing.T) {
	store := newFakeBeliefArtifacts()
	store.err = errors.New("postgres is down")
	b := testTenantBeliefs(t, testSchema(t), store)
	if _, _, err := b.Pin(context.Background(), "acme"); err == nil {
		t.Fatal("Pin succeeded while the store was down")
	}
}

// The store is a required dependency: a nil store fails at construction.
func TestNewTenantBeliefs_RefusesANilStore(t *testing.T) {
	if _, err := newTenantBeliefs(nil, testSchema(t), nil); !errors.Is(err, errNoBeliefArtifacts) {
		t.Fatalf("newTenantBeliefs(nil) = %v, want errNoBeliefArtifacts", err)
	}
}

// A current version with no row is an error, not a silent default.
func TestTenantBeliefs_ACurrentVersionWithNoRowFailsThePin(t *testing.T) {
	store := newFakeBeliefArtifacts()
	store.current["acme"] = 7
	b := testTenantBeliefs(t, testSchema(t), store)
	if _, _, err := b.Pin(context.Background(), "acme"); err == nil {
		t.Fatal("Pin succeeded for a current version with no row")
	}
}

// A replay of a finished mission reads the version that the mission pinned,
// not the current version, after the current version changed.
func TestTenantBeliefs_AReplayReadsThePinnedVersion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newFakeBeliefArtifacts()
	store.makeCurrent("acme", 1)
	b := testTenantBeliefs(t, testSchema(t), store)
	reg := brain.NewRegistry(ctx)
	srv := NewWorldServer(reg, nil)
	eng := reg.For("acme")

	// The mission start records the pin, as executeMission does.
	pinned, release := mustPin(t, b, "acme")
	eng.Submit(brain.MissionStarted{ID: "m1", BeliefModel: pinned})
	eng.Submit(brain.MissionDone{ID: "m1", Outcome: brain.MissionCompleted})
	deadline := time.Now().Add(2 * time.Second)
	for len(eng.Events()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	release()

	store.makeCurrent("acme", 2)
	if err := b.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if now, releaseNow := mustPin(t, b, "acme"); now != "tenant-acme-v2" {
		t.Fatalf("a new mission pinned %q, want tenant-acme-v2", now)
	} else {
		releaseNow()
	}

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	frame, err := srv.GetFrameAt(tctx, &worldpb.GetFrameAtRequest{MissionId: "m1", Seq: 99})
	if err != nil {
		t.Fatalf("GetFrameAt: %v", err)
	}
	var got string
	for _, m := range frame.GetMissions() {
		if m.GetId() == "m1" {
			got = m.GetBeliefModel()
		}
	}
	if got != "tenant-acme-v1" {
		t.Fatalf("the replay of m1 reads belief version %q, want the pinned tenant-acme-v1", got)
	}
}

// initTenantBeliefs refuses to start without the platform database. Start
// opens the database first, so this is a wiring defect, not a degraded mode.
func TestInitTenantBeliefs_RefusesToStartWithoutTheDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &daemonImpl{
		config: &config.Config{Belief: config.BeliefConfig{ReloadInterval: time.Hour}},
		logger: observability.NewLogger(observability.ConfigFromEnv()),
	}
	if err := d.initTenantBeliefs(ctx, testSchema(t)); !errors.Is(err, errNoBeliefArtifacts) {
		t.Fatalf("initTenantBeliefs without the database = %v, want errNoBeliefArtifacts", err)
	}
	if d.tenantBeliefs != nil {
		t.Fatal("initTenantBeliefs set a tenant belief source without the database")
	}
}

// initTenantBeliefs builds the source over the open database and starts its
// reload loop.
func TestInitTenantBeliefs_BuildsTheSourceOverTheDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d := &daemonImpl{
		config:     &config.Config{Belief: config.BeliefConfig{ReloadInterval: time.Hour}},
		logger:     observability.NewLogger(observability.ConfigFromEnv()),
		platformDB: db,
	}
	if err := d.initTenantBeliefs(ctx, testSchema(t)); err != nil {
		t.Fatalf("initTenantBeliefs: %v", err)
	}
	if d.tenantBeliefs == nil {
		t.Fatal("initTenantBeliefs set no tenant belief source")
	}
}

// The reload loop swaps an idle tenant without a restart, and it stops when
// its context ends.
func TestTenantBeliefs_RunSwapsWithoutARestart(t *testing.T) {
	store := newFakeBeliefArtifacts()
	b := testTenantBeliefs(t, testSchema(t), store)
	_, release := mustPin(t, b, "acme")
	release()
	store.makeCurrent("acme", 5)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		b.Run(ctx, 5*time.Millisecond)
		close(done)
	}()
	tb := b.forTenant("acme")
	deadline := time.Now().Add(2 * time.Second)
	for (tenantBeliefProvider{tb}).Version() != "tenant-acme-v5" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := (tenantBeliefProvider{tb}).Version(); got != "tenant-acme-v5" {
		t.Fatalf("the loop did not swap the tenant: engine scores with %q", got)
	}

	// A failed refresh keeps the active version.
	store.mu.Lock()
	store.err = errors.New("postgres is down")
	store.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	if got := (tenantBeliefProvider{tb}).Version(); got != "tenant-acme-v5" {
		t.Fatalf("a failed refresh changed the active version to %q", got)
	}
	cancel()
	<-done
}

// A refresh with no known tenant reads nothing.
func TestTenantBeliefs_RefreshWithNoTenantReadsNothing(t *testing.T) {
	store := newFakeBeliefArtifacts()
	store.err = errors.New("must not be read")
	b := testTenantBeliefs(t, testSchema(t), store)
	if err := b.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh with no tenant: %v", err)
	}
}

// A version that the store cannot read, or that does not parse, fails the pin
// and leaves the tenant unloaded, so the next pin tries again.
func TestTenantBeliefs_ABadVersionFailsThePin(t *testing.T) {
	store := newFakeBeliefArtifacts()
	store.makeCurrent("acme", 1)
	store.versionErr = errors.New("row read failed")
	b := testTenantBeliefs(t, testSchema(t), store)
	if _, _, err := b.Pin(context.Background(), "acme"); err == nil {
		t.Fatal("Pin succeeded while the version read failed")
	}

	store.mu.Lock()
	store.versionErr = nil
	store.badModel = true
	store.mu.Unlock()
	if _, _, err := b.Pin(context.Background(), "acme"); err == nil {
		t.Fatal("Pin succeeded with a belief model that does not parse")
	}

	store.mu.Lock()
	store.badModel = false
	store.mu.Unlock()
	if label, release := mustPin(t, b, "acme"); label != "tenant-acme-v1" {
		t.Fatalf("Pin after the store recovered = %q, want tenant-acme-v1", label)
	} else {
		release()
	}
}
