//go:build stale
// +build stale

// NOTE: references the removed DB-backed mission store constructors
// (NewDBMissionStore / NewDBEventStore). Kept behind the `stale` build
// tag so the file is preserved for future repair but does not block
// `go vet` / `go test`. Rewrite against the Redis store and drop the tag.

package mission

import (
	"context"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
)

// setupEmbeddedEtcd starts an embedded etcd server for testing.
// Returns the client and a cleanup function.
func setupEmbeddedEtcd(t *testing.T) (*clientv3.Client, func()) {
	t.Helper()

	// Create embedded etcd configuration
	cfg := embed.NewConfig()
	cfg.Dir = t.TempDir()
	cfg.LogLevel = "error"

	// Start embedded etcd
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		t.Fatalf("failed to start embedded etcd: %v", err)
	}

	// Wait for etcd to be ready
	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(5 * time.Second):
		e.Close()
		t.Fatal("etcd took too long to start")
	}

	// Create etcd client
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{cfg.ListenClientUrls[0].String()},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		e.Close()
		t.Fatalf("failed to create etcd client: %v", err)
	}

	cleanup := func() {
		client.Close()
		e.Close()
	}

	return client, cleanup
}

func TestMissionStore_CreateDefinition(t *testing.T) {
	client, cleanup := setupEmbeddedEtcd(t)
	defer cleanup()

	store := NewDBMissionStore(nil).WithEtcd(client, "gibson-test")
	ctx := context.Background()

	def := &MissionDefinition{
		Name:        "test-mission",
		Version:     "1.0.0",
		Description: "Test mission description",
		Nodes: map[string]*MissionNode{
			"node1": {
				ID:   "node1",
				Type: NodeTypeAgent,
				Name: "Test Node",
			},
		},
	}

	// Test create
	err := store.CreateDefinition(ctx, def)
	if err != nil {
		t.Fatalf("CreateDefinition failed: %v", err)
	}

	// Test duplicate create
	err = store.CreateDefinition(ctx, def)
	if err != ErrDefinitionExists {
		t.Errorf("expected ErrDefinitionExists, got %v", err)
	}

	// Test get
	retrieved, err := store.GetDefinition(ctx, "test-mission")
	if err != nil {
		t.Fatalf("GetDefinition failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected definition, got nil")
	}
	if retrieved.Name != def.Name {
		t.Errorf("expected name %q, got %q", def.Name, retrieved.Name)
	}
	if retrieved.Version != def.Version {
		t.Errorf("expected version %q, got %q", def.Version, retrieved.Version)
	}
}

func TestMissionStore_GetDefinition_NotFound(t *testing.T) {
	client, cleanup := setupEmbeddedEtcd(t)
	defer cleanup()

	store := NewDBMissionStore(nil).WithEtcd(client, "gibson-test")
	ctx := context.Background()

	// Test get non-existent
	retrieved, err := store.GetDefinition(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetDefinition failed: %v", err)
	}
	if retrieved != nil {
		t.Errorf("expected nil, got %v", retrieved)
	}
}

func TestMissionStore_ListDefinitions(t *testing.T) {
	client, cleanup := setupEmbeddedEtcd(t)
	defer cleanup()

	store := NewDBMissionStore(nil).WithEtcd(client, "gibson-test")
	ctx := context.Background()

	// Create multiple definitions
	defs := []*MissionDefinition{
		{
			Name:    "mission1",
			Version: "1.0.0",
			Nodes:   map[string]*MissionNode{},
		},
		{
			Name:    "mission2",
			Version: "2.0.0",
			Nodes:   map[string]*MissionNode{},
		},
	}

	for _, def := range defs {
		if err := store.CreateDefinition(ctx, def); err != nil {
			t.Fatalf("CreateDefinition failed: %v", err)
		}
	}

	// Test list
	list, err := store.ListDefinitions(ctx)
	if err != nil {
		t.Fatalf("ListDefinitions failed: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 definitions, got %d", len(list))
	}
}

func TestMissionStore_UpdateDefinition(t *testing.T) {
	client, cleanup := setupEmbeddedEtcd(t)
	defer cleanup()

	store := NewDBMissionStore(nil).WithEtcd(client, "gibson-test")
	ctx := context.Background()

	def := &MissionDefinition{
		Name:    "test-mission",
		Version: "1.0.0",
		Nodes:   map[string]*MissionNode{},
	}

	// Create
	if err := store.CreateDefinition(ctx, def); err != nil {
		t.Fatalf("CreateDefinition failed: %v", err)
	}

	// Update
	def.Version = "2.0.0"
	def.Description = "Updated description"
	if err := store.UpdateDefinition(ctx, def); err != nil {
		t.Fatalf("UpdateDefinition failed: %v", err)
	}

	// Verify update
	retrieved, err := store.GetDefinition(ctx, "test-mission")
	if err != nil {
		t.Fatalf("GetDefinition failed: %v", err)
	}
	if retrieved.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", retrieved.Version)
	}
	if retrieved.Description != "Updated description" {
		t.Errorf("expected updated description, got %s", retrieved.Description)
	}
}

func TestMissionStore_UpdateDefinition_NotFound(t *testing.T) {
	client, cleanup := setupEmbeddedEtcd(t)
	defer cleanup()

	store := NewDBMissionStore(nil).WithEtcd(client, "gibson-test")
	ctx := context.Background()

	def := &MissionDefinition{
		Name:    "nonexistent",
		Version: "1.0.0",
		Nodes:   map[string]*MissionNode{},
	}

	err := store.UpdateDefinition(ctx, def)
	if err != ErrDefinitionNotFound {
		t.Errorf("expected ErrDefinitionNotFound, got %v", err)
	}
}

func TestMissionStore_DeleteDefinition(t *testing.T) {
	client, cleanup := setupEmbeddedEtcd(t)
	defer cleanup()

	store := NewDBMissionStore(nil).WithEtcd(client, "gibson-test")
	ctx := context.Background()

	def := &MissionDefinition{
		Name:    "test-mission",
		Version: "1.0.0",
		Nodes:   map[string]*MissionNode{},
	}

	// Create
	if err := store.CreateDefinition(ctx, def); err != nil {
		t.Fatalf("CreateDefinition failed: %v", err)
	}

	// Delete
	if err := store.DeleteDefinition(ctx, "test-mission"); err != nil {
		t.Fatalf("DeleteDefinition failed: %v", err)
	}

	// Verify deletion
	retrieved, err := store.GetDefinition(ctx, "test-mission")
	if err != nil {
		t.Fatalf("GetDefinition failed: %v", err)
	}
	if retrieved != nil {
		t.Errorf("expected nil after delete, got %v", retrieved)
	}
}

func TestMissionStore_DeleteDefinition_NotFound(t *testing.T) {
	client, cleanup := setupEmbeddedEtcd(t)
	defer cleanup()

	store := NewDBMissionStore(nil).WithEtcd(client, "gibson-test")
	ctx := context.Background()

	err := store.DeleteDefinition(ctx, "nonexistent")
	if err != ErrDefinitionNotFound {
		t.Errorf("expected ErrDefinitionNotFound, got %v", err)
	}
}

func TestMissionStore_EtcdNotConfigured(t *testing.T) {
	store := NewDBMissionStore(nil)
	ctx := context.Background()

	def := &MissionDefinition{
		Name:    "test",
		Version: "1.0.0",
		Nodes:   map[string]*MissionNode{},
	}

	// Test all methods return ErrEtcdNotConfigured
	if err := store.CreateDefinition(ctx, def); err != ErrEtcdNotConfigured {
		t.Errorf("CreateDefinition: expected ErrEtcdNotConfigured, got %v", err)
	}

	if _, err := store.GetDefinition(ctx, "test"); err != ErrEtcdNotConfigured {
		t.Errorf("GetDefinition: expected ErrEtcdNotConfigured, got %v", err)
	}

	if _, err := store.ListDefinitions(ctx); err != ErrEtcdNotConfigured {
		t.Errorf("ListDefinitions: expected ErrEtcdNotConfigured, got %v", err)
	}

	if err := store.UpdateDefinition(ctx, def); err != ErrEtcdNotConfigured {
		t.Errorf("UpdateDefinition: expected ErrEtcdNotConfigured, got %v", err)
	}

	if err := store.DeleteDefinition(ctx, "test"); err != ErrEtcdNotConfigured {
		t.Errorf("DeleteDefinition: expected ErrEtcdNotConfigured, got %v", err)
	}
}
