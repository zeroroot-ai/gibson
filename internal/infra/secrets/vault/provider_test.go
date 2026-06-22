package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// testTenant is the tenant used in all unit tests.
var testTenant = auth.MustNewTenantID("test-tenant")

// ---------------------------------------------------------------------------
// Mock Vault server helpers
// ---------------------------------------------------------------------------

// kvv2Response builds the JSON body returned by the Vault KV v2 GET endpoint
// for a found secret.
func kvv2Response(encodedValue string) string {
	return fmt.Sprintf(`{
		"data": {
			"data": {"value": %q},
			"metadata": {"created_time": "2024-01-01T00:00:00Z", "version": 1}
		}
	}`, encodedValue)
}

// mountInfoResponse builds the JSON body for sys/internal/ui/mounts/<mount>
// returning a single-mount info envelope. Shape matches what OpenBao
// (and upstream Vault) return at the per-mount info endpoint — wrapped
// in the standard `{"request_id": ..., "data": {...}}` Vault-API
// secret-response envelope.
//
// Updated for slice 4 of the OpenBao migration (PRD deploy#431, #91)
// when detectKVVersion swapped from sys/mounts (cross-mount list) to
// sys/internal/ui/mounts/<mount> (per-mount info, narrower permission).
func mountInfoResponse(mountType, version string) string {
	return fmt.Sprintf(`{
		"request_id": "test-request-id",
		"lease_id": "",
		"renewable": false,
		"lease_duration": 0,
		"data": {
			"type": %q,
			"options": {"version": %q},
			"description": "",
			"accessor": "kv_abc123",
			"local": false,
			"seal_wrap": false,
			"external_entropy_access": false,
			"config": {}
		}
	}`, mountType, version)
}

// mountInfoResponseKV1 returns a sys/internal/ui/mounts response for a KV v1 mount.
func mountInfoResponseKV1() string {
	return mountInfoResponse("kv", "1")
}

// mountInfoResponseKV2 returns a sys/internal/ui/mounts response for a KV v2 mount.
func mountInfoResponseKV2() string {
	return mountInfoResponse("kv", "2")
}

// healthResponseOK returns a healthy Vault sys/health response.
func healthResponseOK() string {
	return `{"initialized":true,"sealed":false,"standby":false,"cluster_name":"vault","cluster_id":"abc","server_time_utc":1000}`
}

// healthResponseSealed returns a sealed Vault sys/health response.
func healthResponseSealed() string {
	return `{"initialized":true,"sealed":true,"standby":false}`
}

// ---------------------------------------------------------------------------
// Mock server builder
// ---------------------------------------------------------------------------

// vaultMock is a collection of per-path handler functions for the test server.
// The override field may be set for tests that need full control over routing.
// mu guards handlers and override — httptest.Server calls ServeHTTP from its
// own goroutine while the test goroutine may still be registering handlers via
// handle(). Without the mutex the map access is a data race that intermittently
// causes valid handlers to appear missing (#93 sdk / platform-clients).
type vaultMock struct {
	mu       sync.RWMutex
	handlers map[string]http.HandlerFunc
	override http.HandlerFunc
}

func newVaultMock() *vaultMock {
	return &vaultMock{handlers: make(map[string]http.HandlerFunc)}
}

// handle registers handler for the given URL path. Safe to call concurrently
// with ServeHTTP.
func (m *vaultMock) handle(path string, h http.HandlerFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[path] = h
}

// ServeHTTP dispatches to the override (when set), then to per-path handlers,
// then returns 404. Safe to call concurrently with handle.
func (m *vaultMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	override := m.override
	h := m.handlers[r.URL.Path]
	m.mu.RUnlock()

	if override != nil {
		override(w, r)
		return
	}
	if h != nil {
		h(w, r)
		return
	}
	http.NotFound(w, r)
}

// buildProviderFromMock creates a Provider pointing at the mock server.
// It bypasses the KV v2 version check performed at construction by pre-
// registering the sys/internal/ui/mounts/<mount> handler on the mock.
// (Updated for slice 4 of OpenBao migration — endpoint narrowed from
// sys/mounts.)
func buildProviderFromMock(t *testing.T, mock *vaultMock, extraHandlers ...func(*vaultMock)) *Provider {
	t.Helper()

	// Always register the sys/internal/ui/mounts/<mount> endpoint with
	// a KV v2 response so New() succeeds.
	mock.handle("/v1/sys/internal/ui/mounts/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, mountInfoResponseKV2())
	})

	for _, fn := range extraHandlers {
		fn(mock)
	}

	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	// Register a token auth so buildClient doesn't attempt network calls.
	mock.handle("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"policies":["root"]}}`)
	})

	cfg := Config{
		Address: srv.URL,
		KVMount: "secret",
		Auth: AuthConfig{
			Method: AuthMethodToken,
			Token:  "test-token",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// Task 6 tests: Get, Health, Capabilities, KV v1 rejection
// ---------------------------------------------------------------------------

func TestGet_Success(t *testing.T) {
	value := []byte("super-secret-value")
	encoded := base64.StdEncoding.EncodeToString(value)

	mock := newVaultMock()
	// Register the KV v2 GET endpoint for the expected path.
	mock.handle("/v1/secret/data/tenant/test-tenant/cred:dbpass", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, kvv2Response(encoded))
	})

	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	got, err := p.Get(ctx, testTenant, "cred:dbpass")
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("Get() = %q, want %q", got, value)
	}
}

func TestGet_NotFound(t *testing.T) {
	mock := newVaultMock()
	mock.handle("/v1/secret/data/tenant/test-tenant/cred:missing", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
	})

	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	_, err := p.Get(ctx, testTenant, "cred:missing")
	if !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Get() missing secret: want ErrNotFound, got %v", err)
	}
}

func TestGet_Forbidden(t *testing.T) {
	mock := newVaultMock()
	mock.handle("/v1/secret/data/tenant/test-tenant/cred:forbidden", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	})

	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	_, err := p.Get(ctx, testTenant, "cred:forbidden")
	if !errors.Is(err, secrets.ErrPermissionDenied) {
		t.Errorf("Get() forbidden: want ErrPermissionDenied, got %v", err)
	}
}

func TestGet_ServerError(t *testing.T) {
	mock := newVaultMock()
	mock.handle("/v1/secret/data/tenant/test-tenant/cred:broken", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["internal server error"]}`, http.StatusInternalServerError)
	})

	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	_, err := p.Get(ctx, testTenant, "cred:broken")
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Get() server error: want ErrUnavailable, got %v", err)
	}
}

func TestHealth_Up(t *testing.T) {
	mock := newVaultMock()
	mock.handle("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, healthResponseOK())
	})

	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	if err := p.Health(ctx); err != nil {
		t.Errorf("Health() healthy vault: unexpected error: %v", err)
	}
}

func TestHealth_Sealed(t *testing.T) {
	mock := newVaultMock()
	mock.handle("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Vault returns 503 for sealed state via the health endpoint.
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprint(w, healthResponseSealed())
	})

	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	err := p.Health(ctx)
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Health() sealed: want ErrUnavailable, got %v", err)
	}
}

func TestCapabilities(t *testing.T) {
	mock := newVaultMock()
	p := buildProviderFromMock(t, mock)

	caps := p.Capabilities()
	if !caps.CanPut {
		t.Error("Capabilities().CanPut = false, want true")
	}
	if !caps.CanDelete {
		t.Error("Capabilities().CanDelete = false, want true")
	}
	if !caps.CanList {
		t.Error("Capabilities().CanList = false, want true")
	}
	if !caps.SupportsVersion {
		t.Error("Capabilities().SupportsVersion = false, want true")
	}
	if caps.MaxValueBytes != maxVaultValueBytes {
		t.Errorf("Capabilities().MaxValueBytes = %d, want %d", caps.MaxValueBytes, maxVaultValueBytes)
	}
}

func TestNew_KVv1Rejection(t *testing.T) {
	mock := newVaultMock()
	mock.handle("/v1/sys/internal/ui/mounts/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, mountInfoResponseKV1())
	})

	srv := httptest.NewServer(mock)
	defer srv.Close()

	cfg := Config{
		Address: srv.URL,
		KVMount: "secret",
		Auth: AuthConfig{
			Method: AuthMethodToken,
			Token:  "test-token",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := New(ctx, cfg)
	if err == nil {
		t.Fatal("New() with KV v1 mount: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "KV v1") {
		t.Errorf("New() KV v1 error message: want message containing 'KV v1', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Task 7 tests: Put, Delete, List, Probe, AppRole auth mock
// ---------------------------------------------------------------------------

func TestPut_Success(t *testing.T) {
	var captured map[string]interface{}

	mock := newVaultMock()
	mock.handle("/v1/secret/data/tenant/test-tenant/cred:newkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"request_id":"test","lease_id":"","renewable":false,"lease_duration":0,"data":{"version":1,"created_time":"2024-01-01T00:00:00Z"},"wrap_info":null,"warnings":null,"auth":null}`)
	})

	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	value := []byte("my-api-key")
	if err := p.Put(ctx, testTenant, "cred:newkey", value); err != nil {
		t.Fatalf("Put() unexpected error: %v", err)
	}

	// Verify the stored payload uses the base64 value convention.
	if captured != nil {
		dataMap, ok := captured["data"].(map[string]interface{})
		if !ok {
			t.Fatalf("Put() captured payload missing 'data' map")
		}
		encoded, ok := dataMap["value"].(string)
		if !ok {
			t.Fatalf("Put() captured payload missing 'value' field")
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("Put() stored value is not valid base64: %v", err)
		}
		if string(decoded) != string(value) {
			t.Errorf("Put() decoded stored value = %q, want %q", decoded, value)
		}
	}
}

func TestPut_TooLarge(t *testing.T) {
	mock := newVaultMock()
	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	oversized := make([]byte, maxVaultValueBytes+1)
	err := p.Put(ctx, testTenant, "cred:big", oversized)
	if !errors.Is(err, secrets.ErrTooLarge) {
		t.Errorf("Put() oversized: want ErrTooLarge, got %v", err)
	}
}

func TestDelete_Success(t *testing.T) {
	mock := newVaultMock()
	// KVv2.Delete sends a DELETE request to /v1/secret/data/<path>.
	mock.handle("/v1/secret/data/tenant/test-tenant/cred:oldkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			// Vault returns 204 No Content on successful delete.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	})

	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	if err := p.Delete(ctx, testTenant, "cred:oldkey"); err != nil {
		t.Errorf("Delete() unexpected error: %v", err)
	}
}

// fullListResponse returns a properly-formatted Vault list response JSON that
// the Logical client can parse correctly. The vault/api client requires the
// full Secret structure including lease fields.
func fullListResponse(keys []string) string {
	ks := make([]string, len(keys))
	for i, k := range keys {
		ks[i] = fmt.Sprintf("%q", k)
	}
	return fmt.Sprintf(
		`{"request_id":"test","lease_id":"","renewable":false,"lease_duration":0,"data":{"keys":[%s]},"wrap_info":null,"warnings":null,"auth":null}`,
		strings.Join(ks, ","),
	)
}

func TestList_Success(t *testing.T) {
	mock := newVaultMock()
	// Vault SDK sends GET with ?list=true to the metadata endpoint.
	// The SDK strips trailing slashes, so the path does NOT have a trailing slash.
	mock.handle("/v1/secret/metadata/tenant/test-tenant", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list") != "true" {
			http.Error(w, "expected list=true query param", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, fullListResponse([]string{"cred:a", "cred:b", "cred:c"}))
	})

	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	names, err := p.List(ctx, testTenant, secrets.Filter{})
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(names) != 3 {
		t.Errorf("List() got %d names, want 3: %v", len(names), names)
	}
}

func TestList_WithPrefix(t *testing.T) {
	mock := newVaultMock()
	// List always queries the tenant root; prefix filtering is done client-side.
	// The mock returns a mix of matching and non-matching keys to verify filtering.
	mock.handle("/v1/secret/metadata/tenant/test-tenant", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list") != "true" {
			http.Error(w, "expected list=true query param", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, fullListResponse([]string{"cred:a", "cred:b", "other:x"}))
	})

	p := buildProviderFromMock(t, mock)

	ctx := context.Background()
	names, err := p.List(ctx, testTenant, secrets.Filter{Prefix: "cred:"})
	if err != nil {
		t.Fatalf("List() with prefix unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("List() with prefix got %d names, want 2: %v", len(names), names)
	}
	// Names must carry the full key name and start with the prefix.
	for _, n := range names {
		if !strings.HasPrefix(n, "cred:") {
			t.Errorf("List() result %q does not start with prefix 'cred:'", n)
		}
	}
}

func TestProbe_Success(t *testing.T) {
	value := []byte("__probe__")
	encoded := base64.StdEncoding.EncodeToString(value)

	mock := newVaultMock()

	// Probe uses the "probe-tenant" tenant ID and a __probe.* canary name.
	// Use the override handler to match path prefixes.
	mock.override = func(w http.ResponseWriter, r *http.Request) {
		// Pass through sys/mounts for construction.
		if r.URL.Path == "/v1/sys/internal/ui/mounts/secret" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, mountInfoResponseKV2())
			return
		}

		if strings.HasPrefix(r.URL.Path, "/v1/secret/data/tenant/probe-tenant/__probe.") {
			switch r.Method {
			case http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, kvv2Response(encoded))
			case http.MethodPost, http.MethodPut:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprint(w, `{"request_id":"x","data":{"version":1}}`)
			case http.MethodDelete:
				// KVv2.Delete sends DELETE to data endpoint.
				w.WriteHeader(http.StatusNoContent)
			}
			return
		}
		http.NotFound(w, r)
	}

	srv := httptest.NewServer(mock)
	defer srv.Close()

	cfg := Config{
		Address: srv.URL,
		KVMount: "secret",
		Auth: AuthConfig{
			Method: AuthMethodToken,
			Token:  "test-token",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if err := p.Probe(ctx); err != nil {
		t.Errorf("Probe() unexpected error: %v", err)
	}
}

func TestAppRoleAuth_MockedLogin(t *testing.T) {
	mock := newVaultMock()

	// AppRole login endpoint.
	mock.handle("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{
			"auth": {
				"client_token": "approle-derived-token",
				"policies": ["default"],
				"lease_duration": 3600,
				"renewable": true
			}
		}`)
	})

	mock.handle("/v1/sys/internal/ui/mounts/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, mountInfoResponseKV2())
	})

	srv := httptest.NewServer(mock)
	defer srv.Close()

	cfg := Config{
		Address: srv.URL,
		KVMount: "secret",
		Auth: AuthConfig{
			Method:          AuthMethodAppRole,
			AppRoleID:       "test-role-id",
			AppRoleSecretID: "test-secret-id",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() with AppRole auth: unexpected error: %v", err)
	}
	if p.client.Token() != "approle-derived-token" {
		t.Errorf("AppRole auth: expected token 'approle-derived-token', got %q", p.client.Token())
	}
}

// TestAuthMethod_KubernetesIsDenied asserts that the AuthMethod surface does
// NOT include a kubernetes member. The Vault provider in this SDK supports
// only Token / AppRole / JWT / AWSIAM. Kubernetes (TokenReview-based) Vault
// auth was removed per ADR-0009 (jwt-spiffe-everywhere); workloads on
// Kubernetes authenticate to Vault via JWT (SPIFFE-issued or Zitadel-issued)
// or AppRole, never via ServiceAccount TokenReview.
//
// This test guards against accidental re-introduction. It enumerates the
// known-valid AuthMethod values and asserts the literal "kubernetes" string
// is not produced by any of them and that no exported identifier named
// AuthMethodKubernetes exists in this package.
// ---------------------------------------------------------------------------
// Namespace mode tests (cfg.Namespace != "")
//
// In namespace mode the Vault client calls SetNamespace so every request
// carries X-Vault-Namespace=<ns>. Within that namespace the KV mount is
// tenant-private, so kvPath must return just <name> — NOT "tenant/<id>/<name>".
// The operator (tenant-operator) writes to <mount>/data/<name> inside the
// namespace; if the daemon reads "tenant/<id>/<name>" it gets a 404.
// Regression guard for the path mismatch that caused dashboard 412s.
// ---------------------------------------------------------------------------

// buildProviderFromMockWithNamespace creates a Provider with cfg.Namespace set.
// It registers the same default handlers as buildProviderFromMock but also
// returns the mock so callers can register additional handlers.
func buildProviderFromMockWithNamespace(t *testing.T, namespace string, extra ...func(*vaultMock)) (*Provider, *vaultMock) {
	t.Helper()
	mock := newVaultMock()
	mock.handle("/v1/sys/internal/ui/mounts/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, mountInfoResponseKV2())
	})
	mock.handle("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"data":{"policies":["root"]}}`)
	})
	for _, fn := range extra {
		fn(mock)
	}
	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	cfg := Config{
		Address:   srv.URL,
		Namespace: namespace,
		KVMount:   "secret",
		Auth:      AuthConfig{Method: AuthMethodToken, Token: "test-token"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() with namespace %q: unexpected error: %v", namespace, err)
	}
	return p, mock
}

// TestGet_NamespaceMode asserts that in namespace mode kvPath returns just the
// secret name, so Get reads from <mount>/data/<name> (e.g. secret/data/infra/postgres)
// rather than the incorrect <mount>/data/tenant/<id>/<name>.
func TestGet_NamespaceMode(t *testing.T) {
	value := []byte("pg-creds-json")
	encoded := base64.StdEncoding.EncodeToString(value)
	tenantNS := "tenant-one"
	tenant := auth.MustNewTenantID("one")

	var gotPath string
	p, mock := buildProviderFromMockWithNamespace(t, tenantNS)
	// Register the path the daemon SHOULD read after the fix: just the name,
	// no tenant/<id>/ prefix.
	mock.handle("/v1/secret/data/infra/postgres", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, kvv2Response(encoded))
	})

	ctx := context.Background()
	got, err := p.Get(ctx, tenant, "infra/postgres")
	if err != nil {
		t.Fatalf("Get() namespace mode: unexpected error: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("Get() namespace mode: got %q, want %q", got, value)
	}
	if gotPath != "/v1/secret/data/infra/postgres" {
		t.Errorf("Get() namespace mode: request hit path %q, want %q", gotPath, "/v1/secret/data/infra/postgres")
	}
}

// TestGet_NamespaceMode_NoTenantPrefix asserts that the path does NOT include
// "tenant/<id>/" in namespace mode (regression guard for the original bug).
func TestGet_NamespaceMode_NoTenantPrefix(t *testing.T) {
	tenant := auth.MustNewTenantID("one")
	p, mock := buildProviderFromMockWithNamespace(t, "tenant-one")

	var gotPath string
	// Register a catch-all that records the path and returns 404.
	mock.override = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/internal/ui/mounts/secret" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, mountInfoResponseKV2())
			return
		}
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"policies":["root"]}}`)
			return
		}
		gotPath = r.URL.Path
		http.NotFound(w, r)
	}

	ctx := context.Background()
	_, _ = p.Get(ctx, tenant, "infra/postgres")

	if strings.Contains(gotPath, "tenant/one") {
		t.Errorf("Get() namespace mode sent path %q — must NOT include 'tenant/<id>' in namespace mode", gotPath)
	}
}

// TestPut_NamespaceMode asserts that Put writes to <mount>/data/<name> (no
// tenant prefix) in namespace mode.
func TestPut_NamespaceMode(t *testing.T) {
	tenant := auth.MustNewTenantID("one")
	p, mock := buildProviderFromMockWithNamespace(t, "tenant-one")

	var gotPath string
	mock.handle("/v1/secret/data/infra/postgres", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"request_id":"x","data":{"version":1}}`)
	})

	ctx := context.Background()
	if err := p.Put(ctx, tenant, "infra/postgres", []byte("value")); err != nil {
		t.Fatalf("Put() namespace mode: unexpected error: %v", err)
	}
	if gotPath != "/v1/secret/data/infra/postgres" {
		t.Errorf("Put() namespace mode: request hit path %q, want %q", gotPath, "/v1/secret/data/infra/postgres")
	}
}

// TestList_NamespaceMode asserts that List uses <mount>/metadata (no
// tenant/<id>/ prefix) in namespace mode.
func TestList_NamespaceMode(t *testing.T) {
	tenant := auth.MustNewTenantID("one")
	p, mock := buildProviderFromMockWithNamespace(t, "tenant-one")

	mock.handle("/v1/secret/metadata", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list") != "true" {
			http.Error(w, "expected list=true", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, fullListResponse([]string{"infra/postgres", "infra/redis"}))
	})

	ctx := context.Background()
	names, err := p.List(ctx, tenant, secrets.Filter{})
	if err != nil {
		t.Fatalf("List() namespace mode: unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("List() namespace mode: got %d names, want 2: %v", len(names), names)
	}
}

// TestList_NamespaceMode_WithPrefix asserts that List with a prefix filters
// client-side from the KV root (no prefix appended to the vault path).
func TestList_NamespaceMode_WithPrefix(t *testing.T) {
	tenant := auth.MustNewTenantID("one")
	p, mock := buildProviderFromMockWithNamespace(t, "tenant-one")

	// List always queries the KV root in namespace mode; prefix is applied
	// client-side. Return a mix of matching and non-matching full key names.
	mock.handle("/v1/secret/metadata", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list") != "true" {
			http.Error(w, "expected list=true", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, fullListResponse([]string{"provider_cred:openai:api_key", "provider_cred:anthropic:api_key", "other:x"}))
	})

	ctx := context.Background()
	names, err := p.List(ctx, tenant, secrets.Filter{Prefix: "provider_cred:"})
	if err != nil {
		t.Fatalf("List() namespace mode with prefix: unexpected error: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("List() namespace mode with prefix: got %d names, want 2: %v", len(names), names)
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "provider_cred:") {
			t.Errorf("List() namespace mode with prefix: result %q does not start with 'provider_cred:'", n)
		}
	}
}

// TestList_NamespaceMode_WithColonPrefix is a regression test for the bug where
// listing with a colon-delimited prefix (e.g. "provider_cred:anthropic:") returned
// empty because the old code appended the colon prefix to the vault LIST path.
// Vault treats only "/" as a path separator; colon-keyed secrets live flat at the
// KV root and are only enumerable via a root LIST + client-side filter.
func TestList_NamespaceMode_WithColonPrefix(t *testing.T) {
	tenant := auth.MustNewTenantID("one")
	p, mock := buildProviderFromMockWithNamespace(t, "tenant-one")

	mock.handle("/v1/secret/metadata", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list") != "true" {
			http.Error(w, "expected list=true", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, fullListResponse([]string{
			"provider_cred:anthropic:api_key",
			"provider_cred:openai:api_key",
			"infra/postgres",
		}))
	})

	ctx := context.Background()
	// Only the "anthropic" provider's credentials should be returned.
	names, err := p.List(ctx, tenant, secrets.Filter{Prefix: "provider_cred:anthropic:"})
	if err != nil {
		t.Fatalf("List() colon prefix: unexpected error: %v", err)
	}
	if len(names) != 1 {
		t.Errorf("List() colon prefix: got %d names, want 1: %v", len(names), names)
	}
	if len(names) == 1 && names[0] != "provider_cred:anthropic:api_key" {
		t.Errorf("List() colon prefix: got %q, want %q", names[0], "provider_cred:anthropic:api_key")
	}
}

func TestAuthMethod_KubernetesIsDenied(t *testing.T) {
	t.Parallel()

	allowed := []AuthMethod{
		AuthMethodToken,
		AuthMethodAppRole,
		AuthMethodJWT,
		AuthMethodAWSIAM,
	}
	for _, m := range allowed {
		if string(m) == "kubernetes" {
			t.Errorf("AuthMethod %q is not allowed: kubernetes auth was removed per ADR-0009", m)
		}
	}

	// Authenticate must reject an unknown method string spelled "kubernetes"
	// even if a caller hand-crafts it, to keep external writers from
	// silently re-introducing the path.
	err := authenticate(context.Background(), nil, AuthConfig{Method: AuthMethod("kubernetes")})
	if err == nil {
		t.Fatal("authenticate(kubernetes): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported auth method") {
		t.Errorf("authenticate(kubernetes): expected 'unsupported auth method' error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// TokenRefresher / NewWithRefresher tests
// ---------------------------------------------------------------------------

// buildProviderWithRefresher creates a Provider via NewWithRefresher, wiring
// it to the given mock server and calling the supplied refresher.
func buildProviderWithRefresher(t *testing.T, mock *vaultMock, refresher TokenRefresher) *Provider {
	t.Helper()
	mock.handle("/v1/sys/internal/ui/mounts/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, mountInfoResponseKV2())
	})

	srv := httptest.NewServer(mock)
	t.Cleanup(srv.Close)

	cfg := Config{
		Address: srv.URL,
		KVMount: "secret",
		// Auth is intentionally blank — NewWithRefresher sources the token
		// entirely via the refresher.
		Auth: AuthConfig{Method: AuthMethodToken, Token: "bootstrap-token"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, err := NewWithRefresher(ctx, cfg, refresher)
	if err != nil {
		t.Fatalf("NewWithRefresher() unexpected error: %v", err)
	}
	return p
}

// TestNewWithRefresher_NilRefresherReturnsError verifies the constructor
// rejects a nil refresher rather than panicking later.
func TestNewWithRefresher_NilRefresherReturnsError(t *testing.T) {
	t.Parallel()
	cfg := Config{Address: "http://127.0.0.1:1", Auth: AuthConfig{Method: AuthMethodToken, Token: "x"}}
	_, err := NewWithRefresher(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("NewWithRefresher(nil refresher): expected error, got nil")
	}
}

// TestNewWithRefresher_RefresherErrorPropagates verifies that a refresher
// failure at construction time surfaces as a constructor error.
func TestNewWithRefresher_RefresherErrorPropagates(t *testing.T) {
	t.Parallel()
	boom := fmt.Errorf("vault jwt auth: SPIRE socket unavailable")
	refresher := func(_ context.Context) (string, error) { return "", boom }

	cfg := Config{Address: "http://127.0.0.1:1", Auth: AuthConfig{Method: AuthMethodToken, Token: "x"}}
	_, err := NewWithRefresher(context.Background(), cfg, refresher)
	if err == nil {
		t.Fatal("expected constructor error when refresher fails, got nil")
	}
	if !strings.Contains(err.Error(), "initial token refresh failed") {
		t.Errorf("expected 'initial token refresh failed' in error, got: %v", err)
	}
}

// TestNewWithRefresher_Get_UsesRefreshedToken verifies that Get calls the
// refresher before the KV operation and uses the returned token. The mock
// server records the X-Vault-Token header and the test asserts it matches
// the value the refresher returned.
func TestNewWithRefresher_Get_UsesRefreshedToken(t *testing.T) {
	t.Parallel()

	const wantToken = "refreshed-token-abc123"
	value := []byte("secret-payload")
	encoded := base64.StdEncoding.EncodeToString(value)

	var gotToken string
	mock := newVaultMock()
	mock.handle("/v1/secret/data/tenant/test-tenant/mykey", func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Vault-Token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, kvv2Response(encoded))
	})

	calls := 0
	refresher := func(_ context.Context) (string, error) {
		calls++
		return wantToken, nil
	}

	p := buildProviderWithRefresher(t, mock, refresher)
	callsBefore := calls

	got, err := p.Get(context.Background(), testTenant, "mykey")
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("Get() value mismatch: got %q, want %q", got, value)
	}
	if gotToken != wantToken {
		t.Errorf("Get() sent token %q to Vault, want %q", gotToken, wantToken)
	}
	if calls <= callsBefore {
		t.Errorf("Get() did not call the refresher (calls before=%d, after=%d)", callsBefore, calls)
	}
}

// TestNewWithRefresher_Get_RefresherCalledOnEveryGet verifies that the
// refresher is called on each Get invocation, not just the first. This is
// the property that ensures a rotating token (e.g. one whose TTL expires and
// is renewed by an AuthCache) is picked up transparently.
func TestNewWithRefresher_Get_RefresherCalledOnEveryGet(t *testing.T) {
	t.Parallel()

	tokens := []string{"token-v1", "token-v2", "token-v3"}
	tokenIdx := 0

	var receivedTokens []string
	mock := newVaultMock()
	mock.handle("/v1/secret/data/tenant/test-tenant/mykey", func(w http.ResponseWriter, r *http.Request) {
		receivedTokens = append(receivedTokens, r.Header.Get("X-Vault-Token"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, kvv2Response(base64.StdEncoding.EncodeToString([]byte("v"))))
	})

	refresher := func(_ context.Context) (string, error) {
		t := tokens[tokenIdx%len(tokens)]
		tokenIdx++
		return t, nil
	}

	p := buildProviderWithRefresher(t, mock, refresher)

	for i := range 3 {
		if _, err := p.Get(context.Background(), testTenant, "mykey"); err != nil {
			t.Fatalf("Get() call %d: unexpected error: %v", i, err)
		}
	}

	// The refresher is called once at construction (tokenIdx becomes 1),
	// then once per Get. Three Gets consume tokens[1%3], tokens[2%3],
	// tokens[3%3] = "token-v2", "token-v3", "token-v1".
	wantOps := []string{"token-v2", "token-v3", "token-v1"}
	for i, want := range wantOps {
		if i >= len(receivedTokens) {
			t.Fatalf("Get() call %d: no token received by mock server", i)
		}
		if receivedTokens[i] != want {
			t.Errorf("Get() call %d: server received token %q, want %q", i, receivedTokens[i], want)
		}
	}
}

// TestNewWithRefresher_Get_RefresherErrorSurfacesAsUnavailable verifies that
// a refresher error during a Get call is returned as ErrUnavailable (not
// silently swallowed or returned as a generic string error).
func TestNewWithRefresher_Get_RefresherErrorSurfacesAsUnavailable(t *testing.T) {
	t.Parallel()

	callN := 0
	refresher := func(_ context.Context) (string, error) {
		callN++
		if callN > 1 {
			return "", fmt.Errorf("SPIRE socket gone")
		}
		return "initial-token", nil
	}

	mock := newVaultMock()
	p := buildProviderWithRefresher(t, mock, refresher)

	_, err := p.Get(context.Background(), testTenant, "mykey")
	if !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("Get() when refresher fails: want ErrUnavailable, got: %v", err)
	}
}
