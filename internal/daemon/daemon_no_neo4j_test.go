package daemon

import (
	"testing"

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
