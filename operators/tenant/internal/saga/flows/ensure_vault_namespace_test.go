/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package flows

// Integration tests for the ensureVaultNamespace saga step (spec
// secrets-tenant-lifecycle Task 19, Requirement 7.1/7.2).
//
// Run shape: hermetic. The test wires the real Vault admin client (from
// internal/clients/vault) against a local httptest.Server that mimics the
// subset of the Vault API the admin client touches, plus the real
// SignupProgress Redis client wrapping miniredis. No docker, no
// kubernetes, no external services. The end result exercises the same
// code paths as the production wiring — every layer except the network
// transport is real.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/signupprogress"
	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
)

const testAttemptID = "11111111-2222-3333-4444-555555555555"

// fakeVault is a minimal in-memory Vault HTTP server. We re-implement it
// here (rather than importing the one in internal/clients/vault) because
// that one is package-private to the vault package and the Task 19 test
// belongs in the flows package.
type fakeVault struct {
	mu                 sync.Mutex
	edition            vaultadmin.Edition
	calls              []string
	existingNamespaces map[string]bool
	existingMounts     map[string]bool
	policies           map[string]string
	jwtRoles           map[string]map[string]any
	// failPolicyWrites returns 500 (transient, ErrUnreachable) for the
	// next N policy write requests. Decrements on each request. Used to
	// test transient-error handling without breaking the happy-path
	// edition detection.
	failPolicyWrites int
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		edition:            vaultadmin.EditionEnterprise,
		existingNamespaces: map[string]bool{},
		existingMounts:     map[string]bool{},
		policies:           map[string]string{},
		jwtRoles:           map[string]map[string]any{},
	}
}

func (f *fakeVault) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
}

func (f *fakeVault) callsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeVault) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		body := map[string]any{"version": "1.18.0", "enterprise": false}
		writeJSON(w, http.StatusOK, body)
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{}})
	})
	mux.HandleFunc("/v1/sys/namespaces/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.mu.Lock()
		defer f.mu.Unlock()
		nsPath := strings.TrimPrefix(r.URL.Path, "/v1/sys/namespaces/")
		switch r.Method {
		case http.MethodPost:
			if f.existingNamespaces[nsPath] {
				writeErrors(w, http.StatusBadRequest, "namespace already exists")
				return
			}
			f.existingNamespaces[nsPath] = true
			writeJSON(w, http.StatusOK, map[string]any{})
		case http.MethodDelete:
			delete(f.existingNamespaces, nsPath)
			w.WriteHeader(http.StatusNoContent)
		}
	})
	mux.HandleFunc("/v1/sys/mounts/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.mu.Lock()
		defer f.mu.Unlock()
		key := r.Header.Get("X-Vault-Namespace") + "::" + strings.TrimPrefix(r.URL.Path, "/v1/sys/mounts/")
		if f.existingMounts[key] {
			writeErrors(w, http.StatusBadRequest, "path is already in use")
			return
		}
		f.existingMounts[key] = true
		writeJSON(w, http.StatusOK, map[string]any{})
	})
	// EnsureTenantNamespace mounts jwt/ inside the tenant namespace via
	// POST /v1/sys/auth/<path> (slice 5 / tenant-operator#171). Mirror
	// the same idempotency behaviour as /v1/sys/mounts/.
	mux.HandleFunc("/v1/sys/auth/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		key := r.Header.Get("X-Vault-Namespace") + "::auth/" + strings.TrimPrefix(r.URL.Path, "/v1/sys/auth/")
		if f.existingMounts[key] {
			writeErrors(w, http.StatusBadRequest, "path is already in use")
			return
		}
		f.existingMounts[key] = true
		writeJSON(w, http.StatusOK, map[string]any{})
	})
	mux.HandleFunc("/v1/sys/policies/acl/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failPolicyWrites > 0 {
			f.failPolicyWrites--
			writeErrors(w, http.StatusInternalServerError, "vault upstream error")
			return
		}
		var body struct {
			Policy string `json:"policy"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.policies[strings.TrimPrefix(r.URL.Path, "/v1/sys/policies/acl/")] = body.Policy
		writeJSON(w, http.StatusOK, map[string]any{})
	})
	mux.HandleFunc("/v1/auth/jwt/role/", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.jwtRoles[strings.TrimPrefix(r.URL.Path, "/v1/auth/jwt/role/")] = body
		writeJSON(w, http.StatusOK, map[string]any{})
	})
	return mux
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
// Test harness
// ---------------------------------------------------------------------------

// integrationHarness ties together the fake Vault server, the real Vault
// admin client, miniredis, and the real SignupProgress Redis client.
type integrationHarness struct {
	t              *testing.T
	fakeVault      *fakeVault
	vaultServer    *httptest.Server
	vaultClient    vaultadmin.AdminClient
	miniredis      *miniredis.Miniredis
	signupProgress *signupprogress.RedisClient
	deps           ProvisionDeps
}

func newIntegrationHarness(t *testing.T) *integrationHarness {
	t.Helper()

	fv := newFakeVault()
	srv := httptest.NewServer(fv.handler())
	t.Cleanup(srv.Close)

	vc, err := vaultadmin.New(vaultadmin.Config{
		Address:          srv.URL,
		AdminToken:       "test-admin-token",
		JWTBoundAudience: "gibson-saas",
	})
	if err != nil {
		t.Fatalf("vaultadmin.New: %v", err)
	}

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	sp := signupprogress.NewRedisClientFromRedis(rdb, 5*time.Minute, signupprogress.DefaultKeyPrefix)

	return &integrationHarness{
		t:              t,
		fakeVault:      fv,
		vaultServer:    srv,
		vaultClient:    vc,
		miniredis:      mr,
		signupProgress: sp,
		deps: ProvisionDeps{
			Vault:          vc,
			SignupProgress: sp,
		},
	}
}

// readProgress retrieves the latest progress payload for the test
// attempt-id, failing the test if the key is missing.
func (h *integrationHarness) readProgress() signupprogress.Progress {
	h.t.Helper()
	raw, err := h.miniredis.Get(signupprogress.DefaultKeyPrefix + testAttemptID)
	if err != nil {
		h.t.Fatalf("miniredis Get progress key: %v", err)
	}
	var p signupprogress.Progress
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		h.t.Fatalf("unmarshal Progress: %v; raw=%q", err, raw)
	}
	return p
}

func newSignupTenant(name string) *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				AnnotationSignupAttemptID: testAttemptID,
			},
		},
		Spec: gibsonv1alpha1.TenantSpec{
			Owner:       "owner@example.com",
			DisplayName: "Display " + name,
		},
		Status: gibsonv1alpha1.TenantStatus{
			Conditions: []metav1.Condition{},
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestEnsureVaultNamespace_HappyPath exercises a brand-new tenant flow
// end to end: the saga step is invoked, the Vault HTTP fake records the
// expected calls, and the SignupProgressStore receives in-flight then
// terminal=ok events under the same attempt ID.
func TestEnsureVaultNamespace_HappyPath(t *testing.T) {
	t.Parallel()
	h := newIntegrationHarness(t)

	tenant := newSignupTenant("happy-path")
	step := newProvisionSecretsBackendStep(h.deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("step returned error: %v", err)
	}
	if !done {
		t.Fatal("expected done=true on success")
	}

	// Vault was actually contacted with the tenant id.
	calls := h.fakeVault.callsSnapshot()
	if len(calls) == 0 {
		t.Fatal("expected at least one Vault HTTP call")
	}
	var sawPolicy, sawJWTRole bool
	for _, c := range calls {
		if strings.Contains(c, "/v1/sys/policies/acl/tenant-happy-path-app") {
			sawPolicy = true
		}
		if strings.Contains(c, "/v1/auth/jwt/role/gibson-plugin-happy-path") {
			sawJWTRole = true
		}
	}
	if !sawPolicy {
		t.Errorf("expected community policy write; calls=%v", calls)
	}
	if !sawJWTRole {
		t.Errorf("expected JWT role write; calls=%v", calls)
	}

	// The progress store landed at terminal=ok under our attempt id.
	progress := h.readProgress()
	if progress.Step != signupprogress.StepProvisioningSecretsBackend {
		t.Errorf("expected step=%q, got %q",
			signupprogress.StepProvisioningSecretsBackend, progress.Step)
	}
	if progress.TerminalState != signupprogress.TerminalOK {
		t.Errorf("expected terminalState=%q, got %q",
			signupprogress.TerminalOK, progress.TerminalState)
	}
	if progress.Error != nil {
		t.Errorf("expected no error payload, got %+v", progress.Error)
	}
}

// TestEnsureVaultNamespace_IdempotentRetry verifies that re-running the
// step against an already-provisioned tenant is a clean no-op:
//   - Vault accepts the duplicate calls (the underlying admin client
//     treats Vault's "already exists" / "path is already in use" as
//     success).
//   - SignupProgress lands at terminalState=ok again on the second run.
//   - The step still returns done=true.
//
// This mirrors the saga-runner's reconcile behaviour, where a step's
// condition is True from a prior pass but the runner may still re-invoke
// the StepFn (e.g., on observed-generation change).
func TestEnsureVaultNamespace_IdempotentRetry(t *testing.T) {
	t.Parallel()
	h := newIntegrationHarness(t)

	tenant := newSignupTenant("idempotent")
	step := newProvisionSecretsBackendStep(h.deps)

	// First invocation.
	done1, err1 := step.Provision(context.Background(), tenant, nil)
	if err1 != nil || !done1 {
		t.Fatalf("first invocation: done=%v err=%v", done1, err1)
	}
	first := h.fakeVault.callsSnapshot()
	if len(first) == 0 {
		t.Fatal("expected Vault calls on first invocation")
	}

	// Second invocation — no error, done=true, more calls recorded.
	done2, err2 := step.Provision(context.Background(), tenant, nil)
	if err2 != nil {
		t.Fatalf("second invocation returned error: %v", err2)
	}
	if !done2 {
		t.Fatal("expected done=true on second invocation (idempotent)")
	}
	second := h.fakeVault.callsSnapshot()
	if len(second) <= len(first) {
		t.Fatalf("expected second invocation to issue Vault calls; first=%d second=%d",
			len(first), len(second))
	}

	// Progress store is still terminal=ok.
	progress := h.readProgress()
	if progress.TerminalState != signupprogress.TerminalOK {
		t.Errorf("expected terminalState=%q on retry, got %q",
			signupprogress.TerminalOK, progress.TerminalState)
	}
}

// TestEnsureVaultNamespace_TransientError_PublishesNoTerminal verifies
// that a transient Vault failure (5xx → ErrUnreachable) does NOT publish
// a terminal=failed event. Only permanent errors surface
// SECRETS_NAMESPACE_FAILED upfront — transient errors fall through to
// the saga runner's normal retry loop, and the in-flight Advance event
// stays current from the dashboard's perspective.
func TestEnsureVaultNamespace_TransientError_PublishesNoTerminal(t *testing.T) {
	t.Parallel()
	h := newIntegrationHarness(t)
	// Inject a 5xx on the next policy write — community-edition path
	// hits this immediately after edition detection.
	h.fakeVault.failPolicyWrites = 5

	tenant := newSignupTenant("transient")
	step := newProvisionSecretsBackendStep(h.deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if err == nil {
		t.Fatal("expected error from step")
	}
	if done {
		t.Fatal("expected done=false on transient failure")
	}
	// Transient errors must NOT be permanent-wrapped — the saga runner
	// will retry on its own.
	if clients.IsPermanent(err) {
		t.Errorf("transient error must not be permanent-wrapped; got %v", err)
	}
	// The progress store carries the in-flight (Advance) write but
	// NOT a terminal=failed payload — transient errors stay in flight
	// from the dashboard's perspective.
	progress := h.readProgress()
	if progress.TerminalState == signupprogress.TerminalFailed {
		t.Fatalf("transient error should not produce terminal=failed; got %+v", progress)
	}
	if progress.TerminalState != signupprogress.TerminalNone {
		t.Errorf("expected in-flight (no terminal); got %q", progress.TerminalState)
	}
}

// TestEnsureVaultNamespace_PermanentErrorSurfacesFailure verifies the
// SECRETS_NAMESPACE_FAILED dashboard signal: a permanent error from the
// Vault admin client (here: invalid tenant id triggering the client's
// validation path) results in:
//   - The step returning a permanent-wrapped error.
//   - SignupProgress carrying terminalState=failed with code
//     SECRETS_NAMESPACE_FAILED.
//
// The saga runner will see IsPermanent(err) and set Blocked, then
// initiate the existing rollback path (Zitadel teardown, etc.).
func TestEnsureVaultNamespace_PermanentErrorSurfacesFailure(t *testing.T) {
	t.Parallel()
	h := newIntegrationHarness(t)

	// The Vault admin client's validateTenantID rejects uppercase as
	// invalid input — wrapping ErrInvalidInput, which the step
	// classifies as permanent.
	tenant := newSignupTenant("BAD-CASE-INVALID")
	step := newProvisionSecretsBackendStep(h.deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if err == nil {
		t.Fatal("expected permanent error")
	}
	if done {
		t.Fatal("expected done=false on permanent error")
	}
	// The wrapped error chain should contain the clients.ErrPermanent
	// sentinel so the saga runner branches to Blocked.
	if !clients.IsPermanent(err) {
		t.Errorf("expected error to be permanent-wrapped; got %v", err)
	}
	// And it must surface the validation root cause for diagnostics.
	if !errors.Is(err, clients.ErrInvalidInput) {
		t.Errorf("expected error chain to include clients.ErrInvalidInput; got %v", err)
	}

	progress := h.readProgress()
	if progress.TerminalState != signupprogress.TerminalFailed {
		t.Fatalf("expected terminalState=%q, got %q (full=%+v)",
			signupprogress.TerminalFailed, progress.TerminalState, progress)
	}
	if progress.Error == nil {
		t.Fatal("expected error payload on permanent failure")
	}
	if progress.Error.Code != signupprogress.CodeSecretsNamespaceFailed {
		t.Errorf("expected code=%q, got %q",
			signupprogress.CodeSecretsNamespaceFailed, progress.Error.Code)
	}
}

// TestEnsureVaultNamespace_NoAttemptID_NoProgressWritten verifies the
// out-of-band-tenant path: a Tenant without the signup-attempt-id
// annotation runs the saga step normally, but no Redis keys are
// written. This protects ops who create tenants via gitops or kubectl
// from unintentional dashboard signup-panel behaviour.
func TestEnsureVaultNamespace_NoAttemptID_NoProgressWritten(t *testing.T) {
	t.Parallel()
	h := newIntegrationHarness(t)

	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "no-attempt-id"},
		Spec:       gibsonv1alpha1.TenantSpec{Owner: "x@example.com"},
		Status:     gibsonv1alpha1.TenantStatus{Conditions: []metav1.Condition{}},
	}
	step := newProvisionSecretsBackendStep(h.deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("step error: %v", err)
	}
	if !done {
		t.Fatal("expected done=true")
	}
	if keys := h.miniredis.Keys(); len(keys) != 0 {
		t.Fatalf("expected no progress keys for tenant without attempt-id annotation; got %v", keys)
	}
}

// The previous TestEnsureVaultNamespace_NilSignupProgress_StillSucceeds
// covered the operator-side "degraded mode" path where SignupProgress
// could be nil. That code path is deleted in the one-code-path epic
// (deploy#199): Redis is required infrastructure, the operator exits 1
// at boot when REDIS_ADDR is unset, and ProvisionDeps.SignupProgress is
// guaranteed non-nil per the operator's startup gate. There is no
// longer a "no Redis" code path to test.

// TestEnsureVaultNamespace_NilVaultPanics documents the one-code-path
// invariant (tenant-operator#197): the step assumes deps.Vault is non-
// nil. The previous "BYO / on-prem nil-Vault publishes terminal-ok"
// test was deleted along with the graceful-nil branch — the operator
// exits 1 at startup when Vault wiring is missing
// (cmd/main.go:buildVaultAdminClient), so this code path is unreachable
// in any well-formed install.
func TestEnsureVaultNamespace_NilVaultPanics(t *testing.T) {
	t.Parallel()
	h := newIntegrationHarness(t)
	h.deps.Vault = nil

	tenant := newSignupTenant("no-vault")
	step := newProvisionSecretsBackendStep(h.deps)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil Vault (one-code-path: tenant-operator#197)")
		}
	}()
	_, _ = step.Provision(context.Background(), tenant, nil)
}
