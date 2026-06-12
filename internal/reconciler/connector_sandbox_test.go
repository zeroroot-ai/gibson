package reconciler

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"
)

// --- fakes ------------------------------------------------------------------

type fakeCatalog struct {
	desired []ConnectorSandbox
	err     error
}

func (f *fakeCatalog) DesiredConnectors(context.Context) ([]ConnectorSandbox, error) {
	return f.desired, f.err
}

type fakeManifest struct {
	// manifests keyed by "tenant\x00connector"; absence => found=false.
	manifests map[string][]byte
	err       error
}

func (f *fakeManifest) ConnectorManifest(_ context.Context, tenant auth.TenantID, connector string) ([]byte, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	m, ok := f.manifests[key(tenant, connector)]
	return m, ok, nil
}

type mintRecord struct{ tenant, connector string }
type fakeIdentity struct {
	mu         sync.Mutex
	minted     []mintRecord
	revoked    []string
	mintErrFor map[string]error // connector -> err
	n          int
}

func (f *fakeIdentity) MintConnectorPrincipal(_ context.Context, tenant auth.TenantID, connector string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.mintErrFor[connector]; ok {
		return "", "", e
	}
	f.minted = append(f.minted, mintRecord{tenant.String(), connector})
	f.n++
	return "principal-" + connector, "token-" + connector, nil
}

func (f *fakeIdentity) RevokeConnectorPrincipal(_ context.Context, principalID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, principalID)
	return nil
}

type launchRecord struct{ tenant, token string }
type fakeLauncher struct {
	mu           sync.Mutex
	launched     []launchRecord
	launchErrFor map[string]error // token suffix (connector) -> err
}

func (f *fakeLauncher) Launch(_ context.Context, tenant auth.TenantID, _ []byte, token string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	connector := token[len("token-"):]
	if e, ok := f.launchErrFor[connector]; ok {
		return "", e
	}
	f.launched = append(f.launched, launchRecord{tenant.String(), token})
	return "sandbox-" + connector, nil
}

type fakeInventory struct {
	mu      sync.Mutex
	entries map[string]InventoryEntry
	putErr  error
}

func newFakeInventory(seed ...InventoryEntry) *fakeInventory {
	inv := &fakeInventory{entries: map[string]InventoryEntry{}}
	for _, e := range seed {
		inv.entries[key(e.Tenant, e.Connector)] = e
	}
	return inv
}

func (f *fakeInventory) List(context.Context) ([]InventoryEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]InventoryEntry, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeInventory) Put(_ context.Context, e InventoryEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	f.entries[key(e.Tenant, e.Connector)] = e
	return nil
}

// helper to build a reconciler with all fakes wired.
func newTestReconciler(cat *fakeCatalog, man *fakeManifest, id *fakeIdentity, l *fakeLauncher, inv *fakeInventory) *ConnectorSandboxReconciler {
	return NewConnectorSandboxReconciler(ConnectorSandboxConfig{
		Catalog: cat, Manifest: man, Identity: id, Launcher: l, Inventory: inv,
	})
}

func manifestsFor(pairs ...ConnectorSandbox) map[string][]byte {
	m := map[string][]byte{}
	for _, p := range pairs {
		m[key(p.Tenant, p.Connector)] = []byte("apiVersion: connector.gibson.zeroroot.ai/v1\nkind: Connector\nname: " + p.Connector)
	}
	return m
}

// --- tests ------------------------------------------------------------------

func TestReconcile_Enable_LaunchesAndRecords(t *testing.T) {
	want := ConnectorSandbox{Tenant: auth.MustNewTenantID("acme"), Connector: "connector-gitlab"}
	cat := &fakeCatalog{desired: []ConnectorSandbox{want}}
	man := &fakeManifest{manifests: manifestsFor(want)}
	id := &fakeIdentity{}
	l := &fakeLauncher{}
	inv := newFakeInventory()

	newTestReconciler(cat, man, id, l, inv).reconcile(context.Background())

	if len(l.launched) != 1 {
		t.Fatalf("expected 1 launch, got %d", len(l.launched))
	}
	if len(id.minted) != 1 {
		t.Errorf("expected 1 principal minted, got %d", len(id.minted))
	}
	got, _ := inv.List(context.Background())
	if len(got) != 1 || got[0].SandboxID != "sandbox-connector-gitlab" {
		t.Errorf("inventory not recorded correctly: %+v", got)
	}
}

func TestReconcile_AlreadyRunning_NoOp(t *testing.T) {
	d := ConnectorSandbox{Tenant: auth.MustNewTenantID("acme"), Connector: "connector-gitlab"}
	cat := &fakeCatalog{desired: []ConnectorSandbox{d}}
	man := &fakeManifest{manifests: manifestsFor(d)}
	id := &fakeIdentity{}
	l := &fakeLauncher{}
	inv := newFakeInventory(InventoryEntry{Tenant: auth.MustNewTenantID("acme"), Connector: "connector-gitlab", SandboxID: "sandbox-x"})

	newTestReconciler(cat, man, id, l, inv).reconcile(context.Background())

	if len(l.launched) != 0 {
		t.Errorf("already-running connector must not relaunch, got %d launches", len(l.launched))
	}
	if len(id.minted) != 0 {
		t.Errorf("already-running connector must not mint an identity, got %d", len(id.minted))
	}
}

func TestReconcile_Idempotent_AcrossTwoPasses(t *testing.T) {
	d := ConnectorSandbox{Tenant: auth.MustNewTenantID("acme"), Connector: "connector-gitlab"}
	cat := &fakeCatalog{desired: []ConnectorSandbox{d}}
	man := &fakeManifest{manifests: manifestsFor(d)}
	id := &fakeIdentity{}
	l := &fakeLauncher{}
	inv := newFakeInventory()
	r := newTestReconciler(cat, man, id, l, inv)

	r.reconcile(context.Background())
	r.reconcile(context.Background())

	if len(l.launched) != 1 {
		t.Errorf("two passes must launch exactly once, got %d", len(l.launched))
	}
}

func TestReconcile_MissingManifest_Skips(t *testing.T) {
	d := ConnectorSandbox{Tenant: auth.MustNewTenantID("acme"), Connector: "connector-ghost"}
	cat := &fakeCatalog{desired: []ConnectorSandbox{d}}
	man := &fakeManifest{manifests: map[string][]byte{}} // no manifest on record
	id := &fakeIdentity{}
	l := &fakeLauncher{}
	inv := newFakeInventory()

	newTestReconciler(cat, man, id, l, inv).reconcile(context.Background())

	if len(l.launched) != 0 || len(id.minted) != 0 {
		t.Errorf("missing-manifest connector must not launch or mint: launches=%d minted=%d", len(l.launched), len(id.minted))
	}
}

func TestReconcile_LaunchFailure_RevokesPrincipal_AndIsolates(t *testing.T) {
	bad := ConnectorSandbox{Tenant: auth.MustNewTenantID("acme"), Connector: "connector-bad"}
	good := ConnectorSandbox{Tenant: auth.MustNewTenantID("acme"), Connector: "connector-good"}
	cat := &fakeCatalog{desired: []ConnectorSandbox{bad, good}}
	man := &fakeManifest{manifests: manifestsFor(bad, good)}
	id := &fakeIdentity{}
	l := &fakeLauncher{launchErrFor: map[string]error{"connector-bad": errors.New("setec boom")}}
	inv := newFakeInventory()

	newTestReconciler(cat, man, id, l, inv).reconcile(context.Background())

	// The good connector still launched (one failure does not block others).
	if len(l.launched) != 1 || l.launched[0].token != "token-connector-good" {
		t.Errorf("good connector must still launch despite bad one's failure: %+v", l.launched)
	}
	// The failed launch's principal was revoked (no identity leak).
	if len(id.revoked) != 1 || id.revoked[0] != "principal-connector-bad" {
		t.Errorf("failed launch must revoke its principal, got revoked=%v", id.revoked)
	}
	// Only the good connector is in the inventory.
	got, _ := inv.List(context.Background())
	if len(got) != 1 || got[0].Connector != "connector-good" {
		t.Errorf("only the good connector should be recorded, got %+v", got)
	}
}

func TestReconcile_MintFailure_NoLaunch(t *testing.T) {
	d := ConnectorSandbox{Tenant: auth.MustNewTenantID("acme"), Connector: "connector-gitlab"}
	cat := &fakeCatalog{desired: []ConnectorSandbox{d}}
	man := &fakeManifest{manifests: manifestsFor(d)}
	id := &fakeIdentity{mintErrFor: map[string]error{"connector-gitlab": errors.New("zitadel down")}}
	l := &fakeLauncher{}
	inv := newFakeInventory()

	newTestReconciler(cat, man, id, l, inv).reconcile(context.Background())

	if len(l.launched) != 0 {
		t.Errorf("mint failure must prevent launch, got %d launches", len(l.launched))
	}
}

func TestReconcile_NoDesired_NoOp(t *testing.T) {
	cat := &fakeCatalog{desired: nil}
	r := newTestReconciler(cat, &fakeManifest{}, &fakeIdentity{}, &fakeLauncher{}, newFakeInventory())
	r.reconcile(context.Background()) // must not panic on nil deps usage
}
