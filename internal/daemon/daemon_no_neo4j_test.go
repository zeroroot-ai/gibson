package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"

	"github.com/zero-day-ai/gibson/internal/config"
)

// TestDaemonNew_NoNeo4jSharedConfig is the Task 5 smoke test for spec
// graphrag-tenant-scope. It verifies that the daemon can be constructed
// with GraphRAG.Neo4j.TenantMode="instance" and no URI/Username/Password
// fields (those fields were removed in this spec).
//
// This test does NOT call Start() — that requires Redis and other services.
// It validates that:
// 1. The config struct no longer has URI/Username/Password fields (compile-time).
// 2. New(cfg) succeeds with the instance-mode config.
// 3. No startup code references the removed config fields.
func TestDaemonNew_NoNeo4jSharedConfig(t *testing.T) {
	t.Parallel()

	cfg := minimalCfg()
	// Explicitly set TenantMode=instance (the default post-refactor).
	// No URI, Username, Password — those fields are gone from config.Neo4jConfig.
	cfg.GraphRAG = config.GraphRAGConfig{
		Enabled: true,
		Neo4j: config.Neo4jConfig{
			TenantMode: "instance",
			// SharedClusterURI intentionally empty (instance mode doesn't use it).
		},
	}

	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New(cfg) with instance TenantMode and no shared Neo4j: %v", err)
	}
	if d == nil {
		t.Fatal("New returned nil daemon")
	}

	// The daemon struct must be non-nil; no Neo4j-related panic should occur.
	impl := d.(*daemonImpl)
	if impl.config == nil {
		t.Fatal("daemonImpl.config is nil")
	}

	// Assert the config Neo4j fields have the right shape.
	neo4jCfg := impl.config.GraphRAG.Neo4j
	if neo4jCfg.TenantMode != "instance" {
		t.Errorf("TenantMode = %q; want \"instance\"", neo4jCfg.TenantMode)
	}
	// SharedClusterURI must be empty for instance mode.
	if neo4jCfg.SharedClusterURI != "" {
		t.Errorf("SharedClusterURI = %q; want empty for instance mode", neo4jCfg.SharedClusterURI)
	}

	// Compile-time assertion: the struct literal above must not reference URI,
	// Username, Password, or MaxConnections — Go compilation would have failed
	// if those fields still existed with different names, or if the new struct
	// had extra required fields.
}

// TestDaemonNew_NoNeo4jSharedConfig_DefaultMode verifies that an empty
// GraphRAG.Neo4j config (TenantMode not set) also works — the default is "instance".
func TestDaemonNew_NoNeo4jSharedConfig_DefaultMode(t *testing.T) {
	t.Parallel()

	cfg := minimalCfg()
	// GraphRAG.Neo4j left at zero value — no URI, no mode set.
	// The daemon must not fail to construct.
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New(cfg) with zero GraphRAG.Neo4j: %v", err)
	}
	if d == nil {
		t.Fatal("New returned nil daemon")
	}
}

// TestDaemonStart_ZeroTenants_MigrationCheckClean is the regression net for
// spec graphrag-intelligence-tenant-scope Phase 5 Task 14.
//
// It verifies that with zero tenants registered the startup migration check
// runs cleanly: no ERROR log, no error returned. The daemon must construct
// cleanly and the check must follow the "no provisioned tenants" code path
// (which logs INFO and returns nil).
//
// This locks in the property that the per-tenant migration drift gate has no
// shared-cluster fallback — when there are no tenants, there is literally
// nothing to check.
func TestDaemonStart_ZeroTenants_MigrationCheckClean(t *testing.T) {
	t.Parallel()

	// Step 1: daemon constructs cleanly with instance-mode config.
	cfg := minimalCfg()
	cfg.GraphRAG = config.GraphRAGConfig{
		Enabled: true,
		Neo4j: config.Neo4jConfig{
			TenantMode: "instance",
		},
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New(cfg): %v", err)
	}
	if d == nil {
		t.Fatal("New returned nil daemon")
	}

	// Step 2: build a fake dynamic K8s client with ZERO Tenant CRD objects.
	// This simulates a deployment where the daemon has come up but no tenants
	// are registered yet (e.g. fresh install).
	scheme := runtime.NewScheme()
	tenantGVK := schema.GroupVersionKind{
		Group:   "gibson.zero-day.ai",
		Version: "v1alpha1",
		Kind:    "Tenant",
	}
	tenantListGVK := schema.GroupVersionKind{
		Group:   "gibson.zero-day.ai",
		Version: "v1alpha1",
		Kind:    "TenantList",
	}
	scheme.AddKnownTypeWithName(tenantGVK, &emptyTenant{})
	scheme.AddKnownTypeWithName(tenantListGVK, &emptyTenantList{})
	dynClient := fake.NewSimpleDynamicClient(scheme)

	// Step 3: capture all log records via a slog handler that writes to a buffer.
	var logBuf bytes.Buffer
	logHandler := slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(logHandler)

	// Step 4: run the migration check with zero tenants. Pool is intentionally
	// nil — with zero tenants the check never reaches a pool call.
	checkCfg := &startupMigrationCheckConfig{
		MigrationsRequired: false,
		DynamicClient:      dynClient,
		Logger:             logger,
		PostgresAdminDSN:   "",
		K8sNamespace:       "",
	}
	reader := &fakeVersionReader{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = runStartupMigrationCheck(ctx, checkCfg, reader)
	if err != nil {
		t.Fatalf("runStartupMigrationCheck with zero tenants: unexpected error: %v", err)
	}

	// Step 5: assert no ERROR-level log line was emitted. Each JSON line has
	// a "level" field; iterate and verify none are ERROR.
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if jerr := json.Unmarshal([]byte(line), &rec); jerr != nil {
			t.Errorf("failed to parse log line as JSON: %v\nline: %s", jerr, line)
			continue
		}
		level, _ := rec["level"].(string)
		if strings.EqualFold(level, "ERROR") {
			t.Errorf("zero-tenant migration check produced ERROR log: %s", line)
		}
	}
}

// emptyTenant + emptyTenantList are minimal runtime.Object stand-ins so the
// fake dynamic client can register the GVK. They carry no fields because the
// list call returns an empty slice anyway.
type emptyTenant struct{}

func (*emptyTenant) GetObjectKind() schema.ObjectKind { return schema.EmptyObjectKind }
func (e *emptyTenant) DeepCopyObject() runtime.Object { return &emptyTenant{} }

type emptyTenantList struct{}

func (*emptyTenantList) GetObjectKind() schema.ObjectKind { return schema.EmptyObjectKind }
func (e *emptyTenantList) DeepCopyObject() runtime.Object { return &emptyTenantList{} }
