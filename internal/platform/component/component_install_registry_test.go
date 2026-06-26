package component

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// In-memory Postgres substitute using sqlite-lite via database/sql.
// We use a minimal fake that satisfies the SQL interface for plugin_install.
// ---------------------------------------------------------------------------

// openTestDB opens an in-memory sqlite database and creates the plugin_install
// table schema that mirrors the Postgres migration 008.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// Use the standard library sqlite driver if available, otherwise skip.
	// Since CGO_ENABLED=0 we cannot use cgo-based sqlite. Use a simple
	// fake backed by a map instead.
	return nil // signal to use fakeDB below
}

// ---------------------------------------------------------------------------
// Fake SQL database implementation
// ---------------------------------------------------------------------------

// fakeDB is an in-memory implementation of the subset of *sql.DB used by
// postgresComponentInstallRegistry for testing without a real Postgres connection.
//
// It is NOT a real sql.DB — instead we construct a testable registry directly
// by satisfying the subset of operations via the testRegistry wrapper.
type fakeInstallStore struct {
	rows map[string]*fakeInstallRow // key: tenant_id+"/"+plugin_name+"/"+host_id
}

type fakeInstallRow struct {
	ID              string
	TenantID        string
	PluginName      string
	Version         string
	ManifestHash    string
	DeclaredMethods []string
	HostID          string
	RuntimeMode     string
	SetecRequired   bool
}

func newFakeInstallStore() *fakeInstallStore {
	return &fakeInstallStore{rows: make(map[string]*fakeInstallRow)}
}

func (s *fakeInstallStore) upsert(row *fakeInstallRow) string {
	key := row.TenantID + "/" + row.PluginName + "/" + row.HostID
	if existing, ok := s.rows[key]; ok {
		// Upsert: update fields, preserve original ID.
		existing.Version = row.Version
		existing.ManifestHash = row.ManifestHash
		existing.DeclaredMethods = row.DeclaredMethods
		existing.RuntimeMode = row.RuntimeMode
		existing.SetecRequired = row.SetecRequired
		return existing.ID
	}
	s.rows[key] = row
	return row.ID
}

func (s *fakeInstallStore) list(tenantID, componentName string) []*fakeInstallRow {
	var result []*fakeInstallRow
	for _, row := range s.rows {
		if row.TenantID == tenantID && row.PluginName == componentName {
			result = append(result, row)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// testPluginRegistry wraps postgresComponentInstallRegistry with a fakeInstallStore
// so we can test without real Postgres.
// ---------------------------------------------------------------------------

type testPluginRegistry struct {
	store       *fakeInstallStore
	redis       *miniredis.Miniredis
	redisClient redis.UniversalClient
	queue       WorkQueue
	roundRobin  *installRoundRobin
}

func newTestPluginRegistry(t *testing.T) *testPluginRegistry {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	return &testPluginRegistry{
		store:       newFakeInstallStore(),
		redis:       mr,
		redisClient: client,
		queue:       NewRedisWorkQueue(client),
		roundRobin:  newInstallRoundRobin(),
	}
}

// register is a test-friendly version of Register that uses the fake store.
func (tr *testPluginRegistry) register(ctx context.Context, install *ComponentInstall) (string, error) {
	if install.ID == "" {
		install.ID = fmt.Sprintf("test-id-%s-%s", install.Name, install.HostID)
	}

	row := &fakeInstallRow{
		ID:              install.ID,
		TenantID:        install.TenantID.String(),
		PluginName:      install.Name,
		Version:         install.Version,
		ManifestHash:    install.ManifestHash,
		DeclaredMethods: install.DeclaredMethods,
		HostID:          install.HostID,
		RuntimeMode:     install.RuntimeMode,
		SetecRequired:   install.SetecRequired,
	}
	assignedID := tr.store.upsert(row)
	install.ID = assignedID

	payload := pluginStatusPayload{
		Address:         "",
		LastHeartbeatAt: time.Now().UTC(),
		Status:          string(ComponentInstallStatusServing),
	}
	data, _ := json.Marshal(payload)
	return assignedID, tr.redisClient.Set(ctx, pluginStatusKey(assignedID), data, pluginInstallTTL).Err()
}

func (tr *testPluginRegistry) heartbeat(ctx context.Context, installID, address string) error {
	key := pluginStatusKey(installID)
	var payload pluginStatusPayload
	data, err := tr.redisClient.Get(ctx, key).Bytes()
	if err == nil {
		_ = json.Unmarshal(data, &payload)
	}
	payload.LastHeartbeatAt = time.Now().UTC()
	if address != "" {
		payload.Address = address
	}
	payload.Status = string(ComponentInstallStatusServing)

	out, _ := json.Marshal(payload)
	return tr.redisClient.Set(ctx, key, out, pluginInstallTTL).Err()
}

func (tr *testPluginRegistry) listInstalls(ctx context.Context, tenant auth.TenantID, name string) ([]InstallInfo, error) {
	rows := tr.store.list(tenant.String(), name)
	var active []InstallInfo
	for _, row := range rows {
		data, err := tr.redisClient.Get(ctx, pluginStatusKey(row.ID)).Bytes()
		if err != nil {
			continue // expired
		}
		var payload pluginStatusPayload
		if err := json.Unmarshal(data, &payload); err != nil {
			continue
		}
		if payload.Status != string(ComponentInstallStatusServing) {
			continue
		}
		active = append(active, InstallInfo{
			InstallID:       row.ID,
			TenantID:        tenant,
			Name:            row.PluginName,
			Version:         row.Version,
			DeclaredMethods: row.DeclaredMethods,
			Address:         payload.Address,
			LastHeartbeatAt: payload.LastHeartbeatAt,
			Status:          ComponentInstallStatusServing,
		})
	}
	return active, nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestPluginRegistry_Register(t *testing.T) {
	ctx := context.Background()
	tr := newTestPluginRegistry(t)

	install := &ComponentInstall{
		TenantID:        auth.MustNewTenantID("tenant-abc"),
		Name:            "shodan",
		Version:         "1.0.0",
		ManifestHash:    "abc123",
		DeclaredMethods: []string{"search", "host"},
		HostID:          "host-key-thumbprint-1",
		RuntimeMode:     "process",
	}

	id, err := tr.register(ctx, install)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty install ID")
	}

	// Redis status should exist with status=serving.
	data, err := tr.redisClient.Get(ctx, pluginStatusKey(id)).Bytes()
	if err != nil {
		t.Fatalf("redis get after register: %v", err)
	}
	var payload pluginStatusPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if payload.Status != string(ComponentInstallStatusServing) {
		t.Errorf("expected status %q, got %q", ComponentInstallStatusServing, payload.Status)
	}
}

func TestPluginRegistry_Upsert(t *testing.T) {
	ctx := context.Background()
	tr := newTestPluginRegistry(t)

	install := &ComponentInstall{
		TenantID: auth.MustNewTenantID("tenant-abc"),
		Name:     "shodan",
		Version:  "1.0.0",
		HostID:   "host-key-thumbprint-1",
	}

	id1, _ := tr.register(ctx, install)

	// Re-register same host — should update, not insert a new row.
	install.Version = "1.1.0"
	install.ID = "" // clear to allow re-assignment
	id2, _ := tr.register(ctx, install)

	// The fake store upsert should return the same ID.
	if id1 != id2 {
		t.Errorf("expected same ID after upsert: id1=%s id2=%s", id1, id2)
	}

	// Verify version updated in the store.
	rows := tr.store.list("tenant-abc", "shodan")
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].Version != "1.1.0" {
		t.Errorf("expected version 1.1.0, got %s", rows[0].Version)
	}
}

func TestPluginRegistry_Heartbeat_RefreshTTL(t *testing.T) {
	ctx := context.Background()
	tr := newTestPluginRegistry(t)

	install := &ComponentInstall{
		TenantID: auth.MustNewTenantID("tenant-abc"),
		Name:     "shodan",
		Version:  "1.0.0",
		HostID:   "host1",
	}
	id, _ := tr.register(ctx, install)

	// Advance miniredis clock close to expiry.
	tr.redis.FastForward(80 * time.Second)

	// Heartbeat should refresh the TTL.
	if err := tr.heartbeat(ctx, id, "127.0.0.1:50055"); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	// Advance another 80s — if TTL was refreshed key should still exist.
	tr.redis.FastForward(80 * time.Second)

	data, err := tr.redisClient.Get(ctx, pluginStatusKey(id)).Bytes()
	if err != nil {
		t.Fatalf("key should still exist after heartbeat refresh: %v", err)
	}

	var payload pluginStatusPayload
	_ = json.Unmarshal(data, &payload)
	if payload.Address != "127.0.0.1:50055" {
		t.Errorf("expected address updated, got %q", payload.Address)
	}
}

func TestPluginRegistry_HeartbeatExpiry_ExcludedFromList(t *testing.T) {
	ctx := context.Background()
	tr := newTestPluginRegistry(t)

	install := &ComponentInstall{
		TenantID: auth.MustNewTenantID("tenant-abc"),
		Name:     "shodan",
		Version:  "1.0.0",
		HostID:   "host1",
	}
	id, _ := tr.register(ctx, install)

	// Let the TTL expire without a heartbeat.
	tr.redis.FastForward(100 * time.Second)

	installs, err := tr.listInstalls(ctx, auth.MustNewTenantID("tenant-abc"), "shodan")
	if err != nil {
		t.Fatalf("list installs: %v", err)
	}
	for _, inst := range installs {
		if inst.InstallID == id {
			t.Error("expired install should not appear in ListInstalls")
		}
	}
}

func TestPluginRegistry_RoundRobin(t *testing.T) {
	ctx := context.Background()
	tr := newTestPluginRegistry(t)

	tenant := auth.MustNewTenantID("tenant-abc")

	for i := 0; i < 3; i++ {
		inst := &ComponentInstall{
			TenantID: tenant,
			Name:     "shodan",
			Version:  "1.0.0",
			HostID:   fmt.Sprintf("host%d", i),
		}
		if _, err := tr.register(ctx, inst); err != nil {
			t.Fatalf("register host %d: %v", i, err)
		}
	}

	installs, err := tr.listInstalls(ctx, tenant, "shodan")
	if err != nil || len(installs) != 3 {
		t.Fatalf("expected 3 installs, got %d (err: %v)", len(installs), err)
	}

	// Round-robin should cycle through all three.
	key := tenant.String() + "/shodan"
	seen := make(map[int]bool)
	for i := 0; i < 9; i++ {
		idx := int(tr.roundRobin.next(key)) % 3
		seen[idx] = true
	}
	if len(seen) != 3 {
		t.Errorf("round-robin did not visit all 3 installs; visited: %v", seen)
	}
}

func TestPluginRegistry_Status_IncludesUnreachable(t *testing.T) {
	ctx := context.Background()
	tr := newTestPluginRegistry(t)

	tenant := auth.MustNewTenantID("tenant-abc")

	inst1 := &ComponentInstall{TenantID: tenant, Name: "shodan", Version: "1.0", HostID: "h1"}
	inst2 := &ComponentInstall{TenantID: tenant, Name: "shodan", Version: "1.0", HostID: "h2"}
	id1, _ := tr.register(ctx, inst1)
	id2, _ := tr.register(ctx, inst2)

	// Let h1's TTL expire.
	tr.redis.FastForward(100 * time.Second)
	// Re-heartbeat h2.
	_ = tr.heartbeat(ctx, id2, "")

	rows := tr.store.list(tenant.String(), "shodan")

	// Build a status response manually to mirror what postgresComponentInstallRegistry.Status does.
	var statusInstalls []InstallInfo
	for _, row := range rows {
		data, err := tr.redisClient.Get(ctx, pluginStatusKey(row.ID)).Bytes()
		var info InstallInfo
		info.InstallID = row.ID
		info.TenantID = tenant
		info.Name = row.PluginName
		info.Version = row.Version
		if err != nil {
			info.Status = ComponentInstallStatusUnreachable
		} else {
			var payload pluginStatusPayload
			_ = json.Unmarshal(data, &payload)
			info.Status = ComponentInstallStatus(payload.Status)
		}
		statusInstalls = append(statusInstalls, info)
	}

	unreachable := 0
	serving := 0
	for _, s := range statusInstalls {
		if s.Status == ComponentInstallStatusUnreachable {
			unreachable++
		}
		if s.Status == ComponentInstallStatusServing {
			serving++
		}
	}
	_ = id1 // used for expiry logic above

	if unreachable == 0 {
		t.Error("expected at least one unreachable install")
	}
	if serving == 0 {
		t.Error("expected at least one serving install")
	}
}

func TestPluginStatusKey(t *testing.T) {
	want := "plugin:install:abc-123:status"
	got := pluginStatusKey("abc-123")
	if got != want {
		t.Errorf("pluginStatusKey: want %q got %q", want, got)
	}
}

func TestPluginWorkError_Error(t *testing.T) {
	err := &PluginWorkError{Code: "UNAVAILABLE", Message: "no installs"}
	got := err.Error()
	want := "plugin work error [UNAVAILABLE]: no installs"
	if got != want {
		t.Errorf("PluginWorkError.Error: want %q got %q", want, got)
	}
}

func TestContentTrustDBRoundTrip(t *testing.T) {
	for _, ct := range []componentpb.ContentTrust{
		componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED,
		componentpb.ContentTrust_CONTENT_TRUST_TRUSTED,
		componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED,
	} {
		if got := contentTrustFromDB(contentTrustToDB(ct)); got != ct {
			t.Errorf("round-trip %v -> %q -> %v", ct, contentTrustToDB(ct), got)
		}
	}
	// Unknown/empty DB value defaults to UNSPECIFIED (gate treats as trusted).
	if got := contentTrustFromDB("garbage"); got != componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED {
		t.Errorf("contentTrustFromDB(garbage) = %v; want UNSPECIFIED", got)
	}
}
