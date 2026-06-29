package main

// seed_first_admin_test.go — unit tests for the seed-first-admin subcommand
// configuration loading and validation (deploy ADR-0006, gibson#1088).
//
// These tests only cover the config-parsing layer; the gRPC dial path is not
// tested here (it requires a live daemon or a mock gRPC server, which belongs
// in integration tests). The key invariants are:
//  1. Missing required env vars produce a clear, actionable error.
//  2. All required env vars present produces a valid config with correct defaults.
//  3. The positional-argument guard fires immediately on unexpected args.

import (
	"context"
	"testing"
)

// TestSeedFirstAdmin_MissingDaemonAddr verifies that a missing GIBSON_DAEMON_ADDR
// returns a clear error before any network call is attempted.
func TestSeedFirstAdmin_MissingDaemonAddr(t *testing.T) {
	t.Setenv("GIBSON_DAEMON_ADDR", "")
	t.Setenv("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("BOOTSTRAP_TENANT_ID", "default")
	t.Setenv("BOOTSTRAP_TENANT_DISPLAY_NAME", "Default Org")

	_, err := loadSeedFirstAdminConfig()
	if err == nil {
		t.Fatal("expected error for missing GIBSON_DAEMON_ADDR, got nil")
	}
}

// TestSeedFirstAdmin_MissingAdminEmail verifies that a missing BOOTSTRAP_ADMIN_EMAIL
// returns a clear error.
func TestSeedFirstAdmin_MissingAdminEmail(t *testing.T) {
	t.Setenv("GIBSON_DAEMON_ADDR", "daemon:50051")
	t.Setenv("BOOTSTRAP_ADMIN_EMAIL", "")
	t.Setenv("BOOTSTRAP_TENANT_ID", "default")
	t.Setenv("BOOTSTRAP_TENANT_DISPLAY_NAME", "Default Org")

	_, err := loadSeedFirstAdminConfig()
	if err == nil {
		t.Fatal("expected error for missing BOOTSTRAP_ADMIN_EMAIL, got nil")
	}
}

// TestSeedFirstAdmin_MissingTenantID verifies that a missing BOOTSTRAP_TENANT_ID
// returns a clear error.
func TestSeedFirstAdmin_MissingTenantID(t *testing.T) {
	t.Setenv("GIBSON_DAEMON_ADDR", "daemon:50051")
	t.Setenv("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("BOOTSTRAP_TENANT_ID", "")
	t.Setenv("BOOTSTRAP_TENANT_DISPLAY_NAME", "Default Org")

	_, err := loadSeedFirstAdminConfig()
	if err == nil {
		t.Fatal("expected error for missing BOOTSTRAP_TENANT_ID, got nil")
	}
}

// TestSeedFirstAdmin_MissingDisplayName verifies that a missing
// BOOTSTRAP_TENANT_DISPLAY_NAME returns a clear error.
func TestSeedFirstAdmin_MissingDisplayName(t *testing.T) {
	t.Setenv("GIBSON_DAEMON_ADDR", "daemon:50051")
	t.Setenv("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("BOOTSTRAP_TENANT_ID", "default")
	t.Setenv("BOOTSTRAP_TENANT_DISPLAY_NAME", "")

	_, err := loadSeedFirstAdminConfig()
	if err == nil {
		t.Fatal("expected error for missing BOOTSTRAP_TENANT_DISPLAY_NAME, got nil")
	}
}

// TestSeedFirstAdmin_ParsesConfig verifies that when all required env vars are
// set, the config is loaded correctly with the right defaults.
func TestSeedFirstAdmin_ParsesConfig(t *testing.T) {
	t.Setenv("GIBSON_DAEMON_ADDR", "gibson-daemon:50051")
	t.Setenv("BOOTSTRAP_ADMIN_EMAIL", "root@acme.example")
	t.Setenv("BOOTSTRAP_TENANT_ID", "acme")
	t.Setenv("BOOTSTRAP_TENANT_DISPLAY_NAME", "Acme Corp")
	t.Setenv("BOOTSTRAP_ADMIN_TIER", "")       // empty → default "team"
	t.Setenv("GIBSON_BOOTSTRAP_MTLS_CERT", "") // empty → insecure transport
	t.Setenv("GIBSON_BOOTSTRAP_MTLS_KEY", "")
	t.Setenv("GIBSON_BOOTSTRAP_MTLS_CA", "")

	cfg, err := loadSeedFirstAdminConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DaemonAddr != "gibson-daemon:50051" {
		t.Errorf("DaemonAddr = %q, want gibson-daemon:50051", cfg.DaemonAddr)
	}
	if cfg.AdminEmail != "root@acme.example" {
		t.Errorf("AdminEmail = %q, want root@acme.example", cfg.AdminEmail)
	}
	if cfg.TenantID != "acme" {
		t.Errorf("TenantID = %q, want acme", cfg.TenantID)
	}
	if cfg.TenantDisplayName != "Acme Corp" {
		t.Errorf("TenantDisplayName = %q, want Acme Corp", cfg.TenantDisplayName)
	}
	// Tier should default to "team" when BOOTSTRAP_ADMIN_TIER is empty.
	if cfg.Tier != "team" {
		t.Errorf("Tier = %q, want team (default)", cfg.Tier)
	}
	// mTLS fields absent.
	if cfg.TLSCertFile != "" || cfg.TLSKeyFile != "" || cfg.TLSCAFile != "" {
		t.Errorf("expected empty mTLS fields, got cert=%q key=%q ca=%q",
			cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSCAFile)
	}
}

// TestSeedFirstAdmin_ExplicitTier verifies that an explicit BOOTSTRAP_ADMIN_TIER
// value overrides the "team" default.
func TestSeedFirstAdmin_ExplicitTier(t *testing.T) {
	t.Setenv("GIBSON_DAEMON_ADDR", "daemon:50051")
	t.Setenv("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
	t.Setenv("BOOTSTRAP_TENANT_ID", "default")
	t.Setenv("BOOTSTRAP_TENANT_DISPLAY_NAME", "Default Org")
	t.Setenv("BOOTSTRAP_ADMIN_TIER", "enterprise")

	cfg, err := loadSeedFirstAdminConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Tier != "enterprise" {
		t.Errorf("Tier = %q, want enterprise", cfg.Tier)
	}
}

// TestSeedFirstAdmin_PositionalArgsRejected verifies that the seed-first-admin
// subcommand rejects positional arguments with a clear usage error.
func TestSeedFirstAdmin_PositionalArgsRejected(t *testing.T) {
	// cmdSeedFirstAdmin validates args before reading env vars, so we don't
	// need to set env vars for this test.
	err := cmdSeedFirstAdmin(context.Background(), []string{"unexpected-arg"})
	if err == nil {
		t.Fatal("expected error for unexpected positional argument, got nil")
	}
}

// TestBuildDialOpts_InsecureWhenNoTLS verifies that buildDialOpts returns an
// insecure option when all mTLS fields are empty.
func TestBuildDialOpts_InsecureWhenNoTLS(t *testing.T) {
	cfg := seedFirstAdminConfig{
		DaemonAddr:  "daemon:50051",
		TLSCertFile: "",
		TLSKeyFile:  "",
		TLSCAFile:   "",
	}
	_, err := buildDialOpts(cfg)
	if err != nil {
		t.Fatalf("buildDialOpts (insecure): %v", err)
	}
}

// TestBuildDialOpts_PartialTLSIsError verifies that a partial mTLS config
// (some but not all three vars set) returns an error.
func TestBuildDialOpts_PartialTLSIsError(t *testing.T) {
	// Only cert+key, no CA.
	cfg := seedFirstAdminConfig{
		DaemonAddr:  "daemon:50051",
		TLSCertFile: "/tmp/cert.pem",
		TLSKeyFile:  "/tmp/key.pem",
		TLSCAFile:   "",
	}
	_, err := buildDialOpts(cfg)
	if err == nil {
		t.Fatal("expected error for partial mTLS config (no CA), got nil")
	}
}
