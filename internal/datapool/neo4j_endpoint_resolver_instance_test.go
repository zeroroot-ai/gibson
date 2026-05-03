package datapool

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/sdk/auth"
)

// mockRegistry implements a fake endpointRegistry for testing.
type mockRegistry struct {
	entries map[string]mockRegistryEntry
}

type mockRegistryEntry struct {
	boltURI    string
	secretName string
	err        error
}

func (m *mockRegistry) Lookup(_ context.Context, tenantID string) (string, string, error) {
	entry, ok := m.entries[tenantID]
	if !ok {
		return "", "", sql.ErrNoRows
	}
	if entry.err != nil {
		return "", "", entry.err
	}
	return entry.boltURI, entry.secretName, nil
}

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

// happySecretsReader returns a mockSecretsReader pre-loaded with the given
// username and password for the standard infra/neo4j paths.
func happySecretsReader(username, password string) *mockSecretsReader {
	return &mockSecretsReader{
		entries: map[string]mockSecretsEntry{
			"infra/neo4j/username": {value: []byte(username)},
			"infra/neo4j/password": {value: []byte(password)},
		},
	}
}

// instanceResolverWithMocks builds an instanceResolver that uses mock
// registry and secrets reader. Only for testing.
func instanceResolverWithMocks(reg *mockRegistry, svc secretsReader) *instanceResolver {
	return &instanceResolver{
		registry: newEndpointRegistry(nil), // pool unused; registry overridden by mockReg
		secrets:  svc,
		cache:    make(map[string]instanceCacheEntry),
		mockReg:  reg,
	}
}

func TestInstanceResolver_HappyPath(t *testing.T) {
	t.Parallel()

	const tenantStr = "tenantabc"
	reg := &mockRegistry{entries: map[string]mockRegistryEntry{
		tenantStr: {boltURI: "bolt://tenantabc-neo4j:7687", secretName: "tenantabc-neo4j-auth"},
	}}
	svc := happySecretsReader("neo4j_user", "s3cr3t")

	r := instanceResolverWithMocks(reg, svc)
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

func TestInstanceResolver_NotRegistered(t *testing.T) {
	t.Parallel()

	reg := &mockRegistry{entries: map[string]mockRegistryEntry{}} // empty — no tenants provisioned
	svc := happySecretsReader("neo4j", "pw")

	r := instanceResolverWithMocks(reg, svc)
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

func TestInstanceResolver_RegistryError(t *testing.T) {
	t.Parallel()

	infraErr := errors.New("postgres: connection refused")
	reg := &mockRegistry{entries: map[string]mockRegistryEntry{
		"tenantx": {err: infraErr},
	}}
	svc := happySecretsReader("neo4j", "pw")

	r := instanceResolverWithMocks(reg, svc)
	tenant := auth.MustNewTenantID("tenantx")

	_, err := r.Resolve(context.Background(), tenant)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// MUST NOT be a NotProvisionedError — it's an infrastructure outage.
	var npErr *NotProvisionedError
	if errors.As(err, &npErr) {
		t.Fatalf("infrastructure error must not be wrapped as NotProvisionedError; got %T", err)
	}
}

func TestInstanceResolver_CredentialsNotInVault(t *testing.T) {
	t.Parallel()

	const tenantStr = "tenantnew"
	reg := &mockRegistry{entries: map[string]mockRegistryEntry{
		tenantStr: {boltURI: "bolt://tenantnew-neo4j:7687", secretName: "tenantnew-neo4j-auth"},
	}}
	// Empty secrets store — simulates operator not yet writing credentials to Vault.
	svc := &mockSecretsReader{entries: map[string]mockSecretsEntry{}}

	r := instanceResolverWithMocks(reg, svc)
	tenant := auth.MustNewTenantID(tenantStr)

	_, err := r.Resolve(context.Background(), tenant)
	if err == nil {
		t.Fatal("expected NotProvisionedError, got nil")
	}
	var npErr *NotProvisionedError
	if !errors.As(err, &npErr) {
		t.Fatalf("expected *NotProvisionedError, got %T: %v", err, err)
	}
	if npErr.Tenant != tenantStr {
		t.Errorf("NotProvisionedError.Tenant: got %q, want %q", npErr.Tenant, tenantStr)
	}
}

func TestInstanceResolver_SecretsInfraError(t *testing.T) {
	t.Parallel()

	const tenantStr = "tenantx2"
	reg := &mockRegistry{entries: map[string]mockRegistryEntry{
		tenantStr: {boltURI: "bolt://tenantx2-neo4j:7687", secretName: "tenantx2-neo4j-auth"},
	}}
	// Secrets broker returns a transient infrastructure error (not NotFound).
	infraErr := status.Errorf(codes.Unavailable, "vault: connection refused")
	svc := &mockSecretsReader{entries: map[string]mockSecretsEntry{
		"infra/neo4j/username": {err: infraErr},
	}}

	r := instanceResolverWithMocks(reg, svc)
	tenant := auth.MustNewTenantID(tenantStr)

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
	reg := &mockRegistry{entries: map[string]mockRegistryEntry{
		tenantStr: {boltURI: "bolt://cached:7687", secretName: "sec"},
	}}
	svc := happySecretsReader("usr", "pw")

	r := instanceResolverWithMocks(reg, svc)
	r.onLookup = func() { calls++ }

	tenant := auth.MustNewTenantID(tenantStr)

	// First call — populates cache.
	ep1, err := r.Resolve(context.Background(), tenant)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	// Second call — should hit cache, not registry.
	ep2, err := r.Resolve(context.Background(), tenant)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if ep1 != ep2 {
		t.Error("second resolve should return same pointer from cache")
	}
	if calls > 1 {
		t.Errorf("registry looked up %d times, want at most 1 (cache hit on 2nd call)", calls)
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
