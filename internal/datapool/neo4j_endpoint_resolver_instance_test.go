package datapool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/sdk/auth"

	pdataplane "github.com/zero-day-ai/gibson/pkg/platform/dataplane"
)

// mockSecretsReader implements secretsReader for testing. It returns
// preconfigured values or errors for named secret paths.
type mockSecretsReader struct {
	entries map[string]mockSecretsEntry
}

type mockSecretsEntry struct {
	value []byte
	err   error
}

func (m *mockSecretsReader) Resolve(_ context.Context, name string) ([]byte, error) {
	entry, ok := m.entries[name]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "secret %q not found", name)
	}
	if entry.err != nil {
		return nil, entry.err
	}
	return entry.value, nil
}

// vaultPayloadReader returns a mockSecretsReader pre-loaded with a valid
// unified Neo4jCredentials JSON payload at the standard infra/neo4j path.
func vaultPayloadReader(boltURI, username, password string) *mockSecretsReader {
	creds := pdataplane.Neo4jCredentials{
		BoltURI:  boltURI,
		Username: username,
		Password: password,
	}
	raw, err := json.Marshal(creds)
	if err != nil {
		panic(fmt.Sprintf("vaultPayloadReader: marshal failed: %v", err))
	}
	return &mockSecretsReader{
		entries: map[string]mockSecretsEntry{
			pdataplane.VaultPathInfraNeo4j: {value: raw},
		},
	}
}

func TestInstanceResolver_HappyPath(t *testing.T) {
	t.Parallel()

	const tenantStr = "tenantabc"
	svc := vaultPayloadReader("bolt://tenantabc-neo4j:7687", "neo4j_user", "s3cr3t")

	r := newInstanceResolver(svc)
	tenant := auth.MustNewTenantID(tenantStr)

	ep, err := r.Resolve(context.Background(), tenant)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep.BoltURI != "bolt://tenantabc-neo4j:7687" {
		t.Errorf("BoltURI: got %q, want bolt://tenantabc-neo4j:7687", ep.BoltURI)
	}
	if ep.Username != "neo4j_user" {
		t.Errorf("Username: got %q, want neo4j_user", ep.Username)
	}
	if ep.Password != "s3cr3t" {
		t.Errorf("Password: got %q, want s3cr3t", ep.Password)
	}
	if ep.Database != "" {
		t.Errorf("Database: got %q, want empty (default DB)", ep.Database)
	}
}

func TestInstanceResolver_NotProvisioned_VaultPathAbsent(t *testing.T) {
	t.Parallel()

	// Empty secrets store — Vault path not present yet.
	svc := &mockSecretsReader{entries: map[string]mockSecretsEntry{}}

	r := newInstanceResolver(svc)
	tenant := auth.MustNewTenantID("notprovisioned")

	_, err := r.Resolve(context.Background(), tenant)
	if err == nil {
		t.Fatal("expected NotProvisionedError, got nil")
	}
	var npErr *NotProvisionedError
	if !errors.As(err, &npErr) {
		t.Fatalf("expected *NotProvisionedError, got %T: %v", err, err)
	}
	if npErr.Tenant != "notprovisioned" {
		t.Errorf("NotProvisionedError.Tenant: got %q, want notprovisioned", npErr.Tenant)
	}
}

func TestInstanceResolver_NotProvisioned_PartialPayload(t *testing.T) {
	t.Parallel()

	// Payload missing the BoltURI — partial write from operator.
	partial := pdataplane.Neo4jCredentials{Username: "user", Password: "pass"}
	raw, _ := json.Marshal(partial)
	svc := &mockSecretsReader{
		entries: map[string]mockSecretsEntry{
			pdataplane.VaultPathInfraNeo4j: {value: raw},
		},
	}

	r := newInstanceResolver(svc)
	tenant := auth.MustNewTenantID("partialprovisioned")

	_, err := r.Resolve(context.Background(), tenant)
	if err == nil {
		t.Fatal("expected NotProvisionedError, got nil")
	}
	var npErr *NotProvisionedError
	if !errors.As(err, &npErr) {
		t.Fatalf("expected *NotProvisionedError, got %T: %v", err, err)
	}
}

func TestInstanceResolver_SecretsInfraError(t *testing.T) {
	t.Parallel()

	// Secrets broker returns a transient infrastructure error (not NotFound).
	infraErr := status.Errorf(codes.Unavailable, "vault: connection refused")
	svc := &mockSecretsReader{entries: map[string]mockSecretsEntry{
		pdataplane.VaultPathInfraNeo4j: {err: infraErr},
	}}

	r := newInstanceResolver(svc)
	tenant := auth.MustNewTenantID("tenantx2")

	_, err := r.Resolve(context.Background(), tenant)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// MUST NOT be a NotProvisionedError — it's a broker infrastructure error.
	var npErr *NotProvisionedError
	if errors.As(err, &npErr) {
		t.Fatalf("infrastructure error must not be wrapped as NotProvisionedError; got %T", err)
	}
}

func TestInstanceResolver_CacheHit(t *testing.T) {
	t.Parallel()

	const tenantStr = "tenantcached"
	calls := 0
	svc := vaultPayloadReader("bolt://cached:7687", "usr", "pw")

	r := newInstanceResolver(svc)
	r.onLookup = func() { calls++ }

	tenant := auth.MustNewTenantID(tenantStr)

	// First call — populates cache.
	ep1, err := r.Resolve(context.Background(), tenant)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	// Second call — should hit cache, not Vault.
	ep2, err := r.Resolve(context.Background(), tenant)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if ep1 != ep2 {
		t.Error("second resolve should return same pointer from cache")
	}
	if calls > 1 {
		t.Errorf("Vault looked up %d times, want at most 1 (cache hit on 2nd call)", calls)
	}
}

// TestIsNotFoundError verifies the gRPC status code detection helper.
func TestIsNotFoundError(t *testing.T) {
	t.Parallel()

	notFound := status.Errorf(codes.NotFound, "secret not found")
	unavail := status.Errorf(codes.Unavailable, "vault down")
	plain := fmt.Errorf("random error")

	if !isNotFoundError(notFound) {
		t.Error("expected true for NotFound gRPC status")
	}
	if isNotFoundError(unavail) {
		t.Error("expected false for Unavailable gRPC status")
	}
	if isNotFoundError(plain) {
		t.Error("expected false for plain error")
	}
	if isNotFoundError(nil) {
		t.Error("expected false for nil error")
	}
}
