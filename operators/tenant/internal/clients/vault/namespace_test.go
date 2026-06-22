/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
)

// fakeVault is a minimal in-memory stand-in for a real Vault server.
// It records calls and returns canned responses keyed by path.
type fakeVault struct {
	mu sync.Mutex
	// calls records (METHOD path) tuples in the order they arrive.
	calls []string
	// existingNamespaces simulates already-created namespaces (returns 400
	// "already exists" when the same namespace is created twice).
	existingNamespaces map[string]bool
	// existingMounts simulates existing mounts; second create returns
	// 400 "path is already in use".
	existingMounts map[string]bool
	// policies records the latest HCL written for each policy name.
	policies map[string]string
	// jwtRoles records role bodies.
	jwtRoles map[string]map[string]any
	// jwtAuthMounted toggles whether GET /v1/sys/auth/jwt returns 200 (mounted)
	// or 400 ("path is not a mount"). Defaults to true so existing tests
	// behave as before; VerifyJWTAuthMounted tests flip this explicitly.
	jwtAuthMounted bool
	// requireToken, when set, rejects requests with a different X-Vault-Token.
	requireToken string
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		existingNamespaces: map[string]bool{},
		existingMounts:     map[string]bool{},
		policies:           map[string]string{},
		jwtRoles:           map[string]map[string]any{},
		jwtAuthMounted:     true,
	}
}

func (f *fakeVault) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		// Slice 5 (#171) deleted runtime resolveEdition; the operator no
		// longer probes /sys/health for edition detection. The fake still
		// answers 200 to satisfy any leftover Ping-style probes — the
		// payload values are no longer load-bearing.
		writeJSON(w, http.StatusOK, map[string]any{
			"version":    "1.18.0",
			"enterprise": true,
		})
	})

	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if !f.checkToken(r) {
			writeErrors(w, http.StatusForbidden, "permission denied")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"display_name": "admin"}})
	})

	// /v1/sys/namespaces/<path>  POST creates, DELETE removes.
	mux.HandleFunc("/v1/sys/namespaces/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if !f.checkToken(r) {
			writeErrors(w, http.StatusForbidden, "permission denied")
			return
		}
		nsPath := strings.TrimPrefix(r.URL.Path, "/v1/sys/namespaces/")
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			if f.existingNamespaces[nsPath] {
				writeErrors(w, http.StatusBadRequest, "namespace already exists")
				return
			}
			f.existingNamespaces[nsPath] = true
			writeJSON(w, http.StatusOK, map[string]any{})
		case http.MethodDelete:
			if !f.existingNamespaces[nsPath] {
				writeErrors(w, http.StatusNotFound, "namespace not found")
				return
			}
			delete(f.existingNamespaces, nsPath)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// /v1/sys/mounts/<path>  POST mounts a backend.
	mux.HandleFunc("/v1/sys/mounts/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if !f.checkToken(r) {
			writeErrors(w, http.StatusForbidden, "permission denied")
			return
		}
		mount := strings.TrimPrefix(r.URL.Path, "/v1/sys/mounts/")
		ns := r.Header.Get("X-Vault-Namespace")
		key := ns + "::" + mount
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.existingMounts[key] {
			writeErrors(w, http.StatusBadRequest, "path is already in use at "+mount+"/")
			return
		}
		f.existingMounts[key] = true
		writeJSON(w, http.StatusOK, map[string]any{})
	})

	// /v1/sys/auth/<path>  GET probes for the existence of an auth mount.
	// Real Vault returns 200 with mount metadata when present and 400
	// ("path is not a mount") when absent. The fake mirrors that contract
	// for the jwt/ mount, gated by jwtAuthMounted.
	mux.HandleFunc("/v1/sys/auth/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if !f.checkToken(r) {
			writeErrors(w, http.StatusForbidden, "permission denied")
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1/sys/auth/")
		switch r.Method {
		case http.MethodGet:
			// VerifyJWTAuthMounted probe.
			if path != "jwt" {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			f.mu.Lock()
			mounted := f.jwtAuthMounted
			f.mu.Unlock()
			if !mounted {
				writeErrors(w, http.StatusBadRequest, "path is not a mount: jwt/")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"type": "jwt", "accessor": "auth_jwt_test"})
		case http.MethodPost:
			// EnsureTenantNamespace mounts jwt/ inside the tenant namespace
			// (slice 5 / tenant-operator#171). Real OpenBao routes
			// auth/jwt strictly by namespace header; the fake records the
			// mount keyed by namespace so namespace-isolation tests can
			// assert it. Idempotent: "path is already in use" on
			// double-mount.
			ns := r.Header.Get("X-Vault-Namespace")
			key := ns + "::auth/" + path
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.existingMounts[key] {
				writeErrors(w, http.StatusBadRequest, "path is already in use at "+path+"/")
				return
			}
			f.existingMounts[key] = true
			writeJSON(w, http.StatusOK, map[string]any{})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// /v1/sys/policies/acl/<name>  PUT writes, DELETE removes.
	mux.HandleFunc("/v1/sys/policies/acl/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if !f.checkToken(r) {
			writeErrors(w, http.StatusForbidden, "permission denied")
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/sys/policies/acl/")
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodPut, http.MethodPost:
			var body struct {
				Policy string `json:"policy"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.policies[name] = body.Policy
			writeJSON(w, http.StatusOK, map[string]any{})
		case http.MethodDelete:
			if _, ok := f.policies[name]; !ok {
				writeErrors(w, http.StatusNotFound, "policy not found")
				return
			}
			delete(f.policies, name)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// /v1/auth/jwt/role/<name>  POST writes, DELETE removes.
	mux.HandleFunc("/v1/auth/jwt/role/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if !f.checkToken(r) {
			writeErrors(w, http.StatusForbidden, "permission denied")
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/auth/jwt/role/")
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.jwtRoles[name] = body
			writeJSON(w, http.StatusOK, map[string]any{})
		case http.MethodDelete:
			if _, ok := f.jwtRoles[name]; !ok {
				writeErrors(w, http.StatusNotFound, "role not found")
				return
			}
			delete(f.jwtRoles, name)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	return mux
}

func (f *fakeVault) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
}

func (f *fakeVault) checkToken(r *http.Request) bool {
	if f.requireToken == "" {
		return true
	}
	return r.Header.Get("X-Vault-Token") == f.requireToken
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErrors(w http.ResponseWriter, status int, msgs ...string) {
	writeJSON(w, status, map[string]any{"errors": msgs})
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

func TestNew_Validates(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty Address")
	}
	if _, err := New(Config{Address: "https://vault"}); err == nil {
		t.Fatal("expected error for missing AdminToken")
	}
	if _, err := New(Config{Address: "://bad", AdminToken: "x"}); err == nil {
		t.Fatal("expected error for invalid Address URL")
	}
}

func TestPing_OKAndUnauthorized(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	fv.requireToken = "good-token"
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	good, _ := New(Config{Address: srv.URL, AdminToken: "good-token"})
	if err := good.Ping(context.Background()); err != nil {
		t.Fatalf("Ping with good token: %v", err)
	}

	bad, _ := New(Config{Address: srv.URL, AdminToken: "bad-token"})
	err := bad.Ping(context.Background())
	if err == nil {
		t.Fatal("expected unauthorized error")
	}
	if !errors.Is(err, clients.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestVerifyJWTAuthMounted(t *testing.T) {
	t.Parallel()

	t.Run("mounted returns nil", func(t *testing.T) {
		t.Parallel()
		fv := newFakeVault()
		fv.jwtAuthMounted = true
		srv := httptest.NewServer(fv.handler())
		defer srv.Close()

		c, _ := New(Config{Address: srv.URL, AdminToken: "x"})
		if err := c.VerifyJWTAuthMounted(context.Background()); err != nil {
			t.Fatalf("expected nil when mounted, got %v", err)
		}
	})

	t.Run("absent returns ErrNotFound naming chart fix", func(t *testing.T) {
		t.Parallel()
		fv := newFakeVault()
		fv.jwtAuthMounted = false
		srv := httptest.NewServer(fv.handler())
		defer srv.Close()

		c, _ := New(Config{Address: srv.URL, AdminToken: "x"})
		err := c.VerifyJWTAuthMounted(context.Background())
		if err == nil {
			t.Fatal("expected error when jwt auth backend absent")
		}
		if !errors.Is(err, clients.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
		if !strings.Contains(err.Error(), "tenant-operator#133") {
			t.Fatalf("expected error to name chart-side fix (tenant-operator#133), got %v", err)
		}
	})
}

func TestEnsureTenantNamespace(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, err := New(Config{
		Address:          srv.URL,
		AdminToken:       "tok",
		JWTAuthMountPath: "auth/jwt",
		JWTBoundAudience: "gibson-saas",
	})
	if err != nil {
		t.Fatal(err)
	}

	ed, err := c.EnsureTenantNamespace(context.Background(), "acme")
	if err != nil {
		t.Fatalf("EnsureTenantNamespace: %v", err)
	}
	if ed != EditionEnterprise {
		t.Fatalf("expected EditionEnterprise, got %q", ed)
	}
	if !fv.existingNamespaces["tenant-acme"] {
		t.Fatalf("expected namespace tenant-acme; have %v", fv.existingNamespaces)
	}
	if _, ok := fv.existingMounts["tenant-acme::secret"]; !ok {
		t.Fatalf("expected secret/ KV mount in tenant-acme namespace; have %v", fv.existingMounts)
	}
	if _, ok := fv.policies["tenant-acme-app"]; !ok {
		t.Fatalf("expected policy tenant-acme-app; have %v", fv.policies)
	}
	role, ok := fv.jwtRoles["gibson-plugin-acme"]
	if !ok {
		t.Fatalf("expected JWT role; have %v", fv.jwtRoles)
	}

	// Slice 5 (PRD deploy#431 / tenant-operator#171, subsuming #151):
	// the role MUST carry bound_audiences (binds to the platform JWT
	// issuer) and MUST NOT carry bound_claims.gibson_tenant — SPIRE
	// JWT-SVIDs cannot satisfy that claim (the SPIRE Workload API has
	// no per-call custom-claim injection). Tenant isolation comes
	// from the role NAME (gibson-plugin-<id>) selecting the
	// per-tenant ACL policy.
	if _, hasBC := role["bound_claims"]; hasBC {
		t.Errorf("role MUST NOT carry bound_claims (tenant-operator#151 / slice 5); got %v", role["bound_claims"])
	}
	ba, ok := role["bound_audiences"].([]any)
	if !ok || len(ba) == 0 {
		t.Fatalf("expected non-empty bound_audiences on role (ADR-0009); have %v", role)
	}
	if ba[0] != "gibson-saas" {
		t.Errorf("bound_audiences[0]: got %v, want %q", ba[0], "gibson-saas")
	}

	// Idempotency: rerun returns nil and same Edition.
	ed2, err := c.EnsureTenantNamespace(context.Background(), "acme")
	if err != nil {
		t.Fatalf("idempotent rerun: %v", err)
	}
	if ed2 != EditionEnterprise {
		t.Fatalf("expected EditionEnterprise on idempotent retry, got %q", ed2)
	}
}

// TestEnsureTenantNamespace_RequiresJWTBoundAudience verifies the
// defensive guard in writeJWTRole: when JWTBoundAudience is empty,
// EnsureTenantNamespace returns ErrInvalidInput rather than silently
// provisioning a role that accepts ANY audience. The operator boot
// path in cmd/main.go already exits 1 on empty
// GIBSON_VAULT_JWT_BOUND_AUDIENCE; this is defense in depth so future
// call paths cannot bypass the constraint (ADR-0009 /
// tenant-operator#147).
func TestEnsureTenantNamespace_RequiresJWTBoundAudience(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	// JWTBoundAudience intentionally left empty.
	c, _ := New(Config{Address: srv.URL, AdminToken: "tok"})
	_, err := c.EnsureTenantNamespace(context.Background(), "tenant-noaud")
	if err == nil {
		t.Fatal("expected error from EnsureTenantNamespace with empty JWTBoundAudience")
	}
	if !errors.Is(err, clients.ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if !strings.Contains(err.Error(), "JWTBoundAudience") {
		t.Errorf("expected error to name the missing config, got %v", err)
	}
	// And the role must not have been written.
	if _, ok := fv.jwtRoles["gibson-plugin-tenant-noaud"]; ok {
		t.Errorf("expected no role written when audience missing; got %v", fv.jwtRoles)
	}
}

func TestEnsureTenantNamespace_RejectsInvalidID(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, _ := New(Config{Address: srv.URL, AdminToken: "tok"})
	for _, bad := range []string{"", "Has-Capital", "has/slash", "has space", "has_underscore"} {
		t.Run(bad, func(t *testing.T) {
			_, err := c.EnsureTenantNamespace(context.Background(), bad)
			if err == nil {
				t.Fatalf("expected error for tenantID %q", bad)
			}
			if !errors.Is(err, clients.ErrInvalidInput) {
				t.Fatalf("expected ErrInvalidInput, got %v", err)
			}
		})
	}
}

func TestDeleteTenantNamespace_Idempotent(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, _ := New(Config{
		Address:          srv.URL,
		AdminToken:       "tok",
		JWTBoundAudience: "gibson-saas",
	})
	if _, err := c.EnsureTenantNamespace(context.Background(), "ent"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteTenantNamespace(context.Background(), "ent"); err != nil {
		t.Fatalf("DeleteTenantNamespace: %v", err)
	}
	if fv.existingNamespaces["tenant-ent"] {
		t.Fatal("expected namespace removed")
	}
	// Idempotent rerun.
	if err := c.DeleteTenantNamespace(context.Background(), "ent"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestPolicyHCLContent(t *testing.T) {
	t.Parallel()

	hcl := tenantPolicyHCL()

	// user/* secrets get full CRUD.
	if !strings.Contains(hcl, `path "secret/data/user/*"`) {
		t.Fatal("tenant policy missing user data path")
	}
	if !strings.Contains(hcl, `path "secret/metadata/user/*"`) {
		t.Fatal("tenant policy missing user metadata path")
	}

	// infra/* secrets are operator-owned and read-only for the daemon.
	if !strings.Contains(hcl, `path "secret/data/infra/*"`) {
		t.Fatal("tenant policy missing infra data path")
	}
	if !strings.Contains(hcl, `path "secret/metadata/infra/*"`) {
		t.Fatal("tenant policy missing infra metadata path")
	}

	// The root metadata LIST is required so the daemon can enumerate
	// colon-delimited provider_cred keys (vault only treats "/" as a path
	// separator; "provider_cred:name:field" is a flat root key enumerable
	// only via LIST at secret/metadata/).
	if !strings.Contains(hcl, `path "secret/metadata"`) {
		t.Fatal("tenant policy missing root metadata list path (required for provider_cred: key enumeration)")
	}

	// The daemon must not be granted a wildcard create/update/delete on the
	// whole mount — that would let it write operator-managed infra material.
	if strings.Contains(hcl, `path "secret/data/*"`) {
		t.Fatal("tenant policy still grants wildcard secret/data/* access")
	}
}

func TestNamingHelpers(t *testing.T) {
	t.Parallel()
	if got := tenantNamespacePath("foo"); got != "tenant-foo" {
		t.Fatalf("tenantNamespacePath: got %q", got)
	}
	if got := tenantPolicyName("foo"); got != "tenant-foo-app" {
		t.Fatalf("tenantPolicyName: got %q", got)
	}
	if got := jwtRoleName("foo"); got != "gibson-plugin-foo" {
		t.Fatalf("jwtRoleName: got %q", got)
	}
}

func TestTenantNamespaceHeader(t *testing.T) {
	t.Parallel()
	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	defer srv.Close()

	c, _ := New(Config{
		Address:          srv.URL,
		AdminToken:       "tok",
		JWTBoundAudience: "gibson-saas",
	})
	if _, err := c.EnsureTenantNamespace(context.Background(), "hdr"); err != nil {
		t.Fatal(err)
	}
	// Verify the mount and policy calls were namespace-scoped (the fake
	// keys mounts under "<ns>::<mount>", so the presence of the keyed entry
	// proves the X-Vault-Namespace header was set).
	if _, ok := fv.existingMounts["tenant-hdr::secret"]; !ok {
		t.Fatalf("expected namespaced mount key; have %v", fv.existingMounts)
	}
}

func TestErrorClassification_Unreachable(t *testing.T) {
	t.Parallel()
	// Point the client at a closed port to provoke a transport error.
	c, _ := New(Config{Address: "http://127.0.0.1:1", AdminToken: "tok"})
	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected error from unreachable Vault")
	}
	if !errors.Is(err, clients.ErrUnreachable) {
		t.Fatalf("expected ErrUnreachable, got %v", err)
	}
}
