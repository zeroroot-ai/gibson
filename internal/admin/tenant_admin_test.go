package admin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/secrets"

	sdksecrets "github.com/zeroroot-ai/platform-clients/secrets"
	adminv1 "github.com/zeroroot-ai/platform-sdk/gen/gibson/admin/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test fakes
// ---------------------------------------------------------------------------

type fakeTenantConfigReader struct {
	cfg secrets.BrokerConfig
	err error
}

func (f *fakeTenantConfigReader) Get(_ context.Context, _ auth.TenantID) (secrets.BrokerConfig, error) {
	if f.err != nil {
		return secrets.BrokerConfig{}, f.err
	}
	return f.cfg, nil
}

type fakeTenantConfigWriter struct {
	saved secrets.BrokerConfig
	err   error
}

func (f *fakeTenantConfigWriter) Set(_ context.Context, _ auth.TenantID, cfg secrets.BrokerConfig, _ string) error {
	if f.err != nil {
		return f.err
	}
	f.saved = cfg
	return nil
}

type fakeProbeFactory struct {
	probeErr     error
	constructErr error
}

func (f *fakeProbeFactory) Construct(_ string, _ []byte) (sdksecrets.Broker, error) {
	if f.constructErr != nil {
		return nil, f.constructErr
	}
	return &probeBroker{err: f.probeErr}, nil
}

type probeBroker struct{ err error }

func (b *probeBroker) Get(_ context.Context, _ auth.TenantID, _ string) ([]byte, error) {
	return nil, sdksecrets.ErrNotFound
}
func (b *probeBroker) Put(_ context.Context, _ auth.TenantID, _ string, _ []byte) error {
	return nil
}
func (b *probeBroker) Delete(_ context.Context, _ auth.TenantID, _ string) error { return nil }
func (b *probeBroker) List(_ context.Context, _ auth.TenantID, _ sdksecrets.Filter) ([]string, error) {
	return nil, nil
}
func (b *probeBroker) Health(_ context.Context) error { return nil }
func (b *probeBroker) Probe(_ context.Context) error  { return b.err }
func (b *probeBroker) Capabilities() sdksecrets.Capabilities {
	return sdksecrets.Capabilities{}
}

// fakeReloader records every Reload(tenant) call so tests can assert
// SetBrokerConfig invokes it exactly once on persist success.
type fakeReloader struct {
	calls []auth.TenantID
}

func (f *fakeReloader) Reload(_ context.Context, tenant auth.TenantID) {
	f.calls = append(f.calls, tenant)
}

// fakeSecretsLister returns a configurable name list for CountSecrets
// tests. Setting err makes List return that error; otherwise it returns
// names verbatim.
type fakeSecretsLister struct {
	names []string
	err   error
}

func (f *fakeSecretsLister) List(_ context.Context, _ sdksecrets.Filter) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.names, nil
}

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

func newTenantTestServer(t *testing.T) (*TenantAdminServer, *fakeTenantConfigReader, *fakeTenantConfigWriter, *fakeProbeFactory, *fakeAuditor, *fakeReloader, *fakeSecretsLister) {
	t.Helper()
	r := &fakeTenantConfigReader{err: secrets.ErrBrokerConfigNotFound}
	w := &fakeTenantConfigWriter{}
	p := &fakeProbeFactory{}
	au := &fakeAuditor{}
	rl := &fakeReloader{}
	sl := &fakeSecretsLister{}
	srv, err := NewTenantAdminServer(TenantAdminConfig{
		Reader:         r,
		Writer:         w,
		ProbeFactory:   p,
		Auditor:        au,
		Reloader:       rl,
		SecretsService: sl,
		Now:            func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewTenantAdminServer: %v", err)
	}
	return srv, r, w, p, au, rl, sl
}

// ---------------------------------------------------------------------------
// GetBrokerConfig tests
// ---------------------------------------------------------------------------

func TestGetBrokerConfig_NotConfigured(t *testing.T) {
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	resp, err := srv.GetBrokerConfig(ctx, &adminv1.GetBrokerConfigRequest{})
	if err != nil {
		t.Fatalf("GetBrokerConfig: %v", err)
	}
	if resp.GetConfigured() {
		t.Errorf("expected configured=false on no-config tenant")
	}
}

func TestGetBrokerConfig_Redacts(t *testing.T) {
	srv, r, _, _, _, _, _ := newTenantTestServer(t)
	r.err = nil
	r.cfg = secrets.BrokerConfig{
		Provider:   "vault",
		ConfigBlob: []byte(`{"address":"https://vault","auth_method":"token","vault_token":"xxx"}`),
	}
	ctx := ctxWithTenant(t, "acme")
	resp, err := srv.GetBrokerConfig(ctx, &adminv1.GetBrokerConfigRequest{})
	if err != nil {
		t.Fatalf("GetBrokerConfig: %v", err)
	}
	if !resp.GetConfigured() {
		t.Errorf("expected configured=true")
	}
	cfg := resp.GetConfig()
	if cfg.GetProvider() != adminv1.BrokerProvider_BROKER_PROVIDER_VAULT {
		t.Errorf("provider mismatch: %v", cfg.GetProvider())
	}
	if cfg.GetAddress() != "https://vault" {
		t.Errorf("address: %q", cfg.GetAddress())
	}
	// SECURITY: vault_token must NOT appear in response. There is no
	// vault_token field on RedactedConfig — it's literally impossible to
	// return it. We assert sensitive_fields_set lists it as configured.
	found := false
	for _, k := range cfg.GetSensitiveFieldsSet() {
		if k == "vault_token" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected vault_token in sensitive_fields_set, got %v", cfg.GetSensitiveFieldsSet())
	}
}

func TestGetBrokerConfig_RequiresTenant(t *testing.T) {
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	_, err := srv.GetBrokerConfig(context.Background(), &adminv1.GetBrokerConfigRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("want PermissionDenied, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ProbeBrokerConfig tests
// ---------------------------------------------------------------------------

func TestProbeBrokerConfig_Success(t *testing.T) {
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ProbeBrokerConfig(ctx, &adminv1.ProbeBrokerConfigRequest{
		Candidate: &adminv1.CandidateConfig{
			Provider:   adminv1.BrokerProvider_BROKER_PROVIDER_VAULT,
			Address:    "https://vault",
			VaultToken: []byte("hvs.xyz"),
		},
	})
	if err != nil {
		t.Fatalf("ProbeBrokerConfig: %v", err)
	}
	if !resp.GetResult().GetOk() {
		t.Errorf("expected ok=true, got %+v", resp.GetResult())
	}
}

func TestProbeBrokerConfig_Failure(t *testing.T) {
	srv, _, _, p, _, _, _ := newTenantTestServer(t)
	p.probeErr = errors.New("vault unauthorized: bad token")
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.ProbeBrokerConfig(ctx, &adminv1.ProbeBrokerConfigRequest{
		Candidate: &adminv1.CandidateConfig{Provider: adminv1.BrokerProvider_BROKER_PROVIDER_VAULT},
	})
	if err != nil {
		t.Fatalf("ProbeBrokerConfig should not return gRPC error on probe failure: %v", err)
	}
	if resp.GetResult().GetOk() {
		t.Errorf("expected ok=false")
	}
	if resp.GetResult().GetErrorClass() != "auth_failed" {
		t.Errorf("expected auth_failed error_class, got %q", resp.GetResult().GetErrorClass())
	}
}

func TestProbeBrokerConfig_RequiresCandidate(t *testing.T) {
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.ProbeBrokerConfig(ctx, &adminv1.ProbeBrokerConfigRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// SetBrokerConfig tests
// ---------------------------------------------------------------------------

func TestSetBrokerConfig_ProbeSuccess_PersistsAndAudits(t *testing.T) {
	srv, _, w, _, au, _, _ := newTenantTestServer(t)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.SetBrokerConfig(ctx, &adminv1.SetBrokerConfigRequest{
		Candidate: &adminv1.CandidateConfig{
			Provider:   adminv1.BrokerProvider_BROKER_PROVIDER_VAULT,
			Address:    "https://vault",
			VaultToken: []byte("hvs.xyz"),
		},
	})
	if err != nil {
		t.Fatalf("SetBrokerConfig: %v", err)
	}
	if !resp.GetProbeResult().GetOk() {
		t.Errorf("expected probe ok=true")
	}
	if w.saved.Provider != "vault" {
		t.Errorf("expected provider=vault saved, got %q", w.saved.Provider)
	}
	if !strings.Contains(string(w.saved.ConfigBlob), "https://vault") {
		t.Errorf("expected address in saved blob")
	}
	if len(au.events) != 1 || au.events[0].Action != "tenant_secrets_backend_configured" {
		t.Errorf("expected tenant_secrets_backend_configured audit, got %+v", au.events)
	}
}

func TestSetBrokerConfig_ProbeFailure_NoPersist(t *testing.T) {
	srv, _, w, p, au, _, _ := newTenantTestServer(t)
	p.probeErr = errors.New("connection refused")
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.SetBrokerConfig(ctx, &adminv1.SetBrokerConfigRequest{
		Candidate: &adminv1.CandidateConfig{
			Provider: adminv1.BrokerProvider_BROKER_PROVIDER_VAULT,
		},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
	if resp.GetProbeResult().GetOk() {
		t.Errorf("expected probe ok=false")
	}
	if resp.GetProbeResult().GetErrorClass() != "network_unreachable" {
		t.Errorf("expected network_unreachable, got %q", resp.GetProbeResult().GetErrorClass())
	}
	if w.saved.Provider != "" {
		t.Errorf("expected nothing saved, got provider=%q", w.saved.Provider)
	}
	if len(au.events) != 0 {
		t.Errorf("expected no audit on probe failure, got %+v", au.events)
	}
}

func TestSetBrokerConfig_RequiresCandidate(t *testing.T) {
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.SetBrokerConfig(ctx, &adminv1.SetBrokerConfigRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
}

// TestSetBrokerConfig_CallsReloadOnSuccess locks in the spec's R2.1 contract:
// after a successful probe + persist, the per-tenant cached SecretsBroker
// MUST be invalidated via Reload(tenant), so the next Resolve/Put/Delete
// rebuilds against the just-persisted config. Without this, in-flight
// callers keep hitting the previously-cached provider until the daemon
// restarts — the regression this whole spec exists to prevent.
func TestSetBrokerConfig_CallsReloadOnSuccess(t *testing.T) {
	srv, _, _, _, _, rl, _ := newTenantTestServer(t)
	ctx := ctxWithTenant(t, "acme")

	if _, err := srv.SetBrokerConfig(ctx, &adminv1.SetBrokerConfigRequest{
		Candidate: &adminv1.CandidateConfig{
			Provider:   adminv1.BrokerProvider_BROKER_PROVIDER_VAULT,
			Address:    "https://vault",
			VaultToken: []byte("hvs.xyz"),
		},
	}); err != nil {
		t.Fatalf("SetBrokerConfig: %v", err)
	}
	if len(rl.calls) != 1 {
		t.Fatalf("expected exactly one Reload call, got %d", len(rl.calls))
	}
	if rl.calls[0].String() != "acme" {
		t.Errorf("Reload(%q), want %q", rl.calls[0].String(), "acme")
	}
}

// TestSetBrokerConfig_NoReloadOnProbeFailure asserts the cache is NOT
// invalidated when the probe fails — there's nothing to invalidate yet.
func TestSetBrokerConfig_NoReloadOnProbeFailure(t *testing.T) {
	srv, _, _, p, _, rl, _ := newTenantTestServer(t)
	p.probeErr = errors.New("connection refused")
	ctx := ctxWithTenant(t, "acme")

	_, _ = srv.SetBrokerConfig(ctx, &adminv1.SetBrokerConfigRequest{
		Candidate: &adminv1.CandidateConfig{Provider: adminv1.BrokerProvider_BROKER_PROVIDER_VAULT},
	})
	if len(rl.calls) != 0 {
		t.Errorf("expected no Reload call on probe failure, got %d", len(rl.calls))
	}
}

// TestSetBrokerConfig_NoReloadOnPersistFailure asserts the cache is NOT
// invalidated when the persist fails — the cache still reflects truth.
func TestSetBrokerConfig_NoReloadOnPersistFailure(t *testing.T) {
	srv, _, w, _, _, rl, _ := newTenantTestServer(t)
	w.err = errors.New("db down")
	ctx := ctxWithTenant(t, "acme")

	_, err := srv.SetBrokerConfig(ctx, &adminv1.SetBrokerConfigRequest{
		Candidate: &adminv1.CandidateConfig{
			Provider:   adminv1.BrokerProvider_BROKER_PROVIDER_VAULT,
			Address:    "https://vault",
			VaultToken: []byte("hvs.xyz"),
		},
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
	if len(rl.calls) != 0 {
		t.Errorf("expected no Reload call on persist failure, got %d", len(rl.calls))
	}
}

// ---------------------------------------------------------------------------
// CountSecrets tests
// ---------------------------------------------------------------------------

func TestCountSecrets_ReturnsLen(t *testing.T) {
	srv, _, _, _, _, _, sl := newTenantTestServer(t)
	sl.names = []string{"db_password", "stripe_key", "openai_key"}
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.CountSecrets(ctx, &adminv1.CountSecretsRequest{})
	if err != nil {
		t.Fatalf("CountSecrets: %v", err)
	}
	if resp.GetCount() != 3 {
		t.Errorf("count: got %d, want 3", resp.GetCount())
	}
}

func TestCountSecrets_Empty(t *testing.T) {
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.CountSecrets(ctx, &adminv1.CountSecretsRequest{})
	if err != nil {
		t.Fatalf("CountSecrets: %v", err)
	}
	if resp.GetCount() != 0 {
		t.Errorf("count: got %d, want 0", resp.GetCount())
	}
}

func TestCountSecrets_RequiresTenant(t *testing.T) {
	srv, _, _, _, _, _, _ := newTenantTestServer(t)
	_, err := srv.CountSecrets(context.Background(), &adminv1.CountSecretsRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("want PermissionDenied, got %v", err)
	}
}

func TestCountSecrets_ListErrorPropagates(t *testing.T) {
	srv, _, _, _, _, _, sl := newTenantTestServer(t)
	sl.err = errors.New("broker timeout")
	ctx := ctxWithTenant(t, "acme")

	_, err := srv.CountSecrets(ctx, &adminv1.CountSecretsRequest{})
	if status.Code(err) != codes.Internal {
		t.Errorf("want Internal, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestRedactProbeMessage_ScrubsTokens(t *testing.T) {
	in := "vault unauthorized: token hvs.AAABBBCCCDDDEEEFFFGGGHHHIIIJJJ rejected"
	out := redactProbeMessage(in)
	if strings.Contains(out, "AAABBBCCC") {
		t.Errorf("expected token scrubbed, got %q", out)
	}
}

func TestClassifyProbeError(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{errors.New("connection refused"), "network_unreachable"},
		{errors.New("no such host"), "network_unreachable"},
		{errors.New("authentication failed"), "auth_failed"},
		{errors.New("unauthorized: invalid token"), "auth_failed"},
		{errors.New("mount kv/ does not exist"), "mount_path_invalid"},
		{errors.New("something weird"), "internal"},
	}
	for _, tc := range tests {
		if got := classifyProbeError(tc.err); got != tc.want {
			t.Errorf("classifyProbeError(%q): got %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestProviderEnumStringRoundtrip(t *testing.T) {
	enums := []adminv1.BrokerProvider{
		adminv1.BrokerProvider_BROKER_PROVIDER_VAULT,
		adminv1.BrokerProvider_BROKER_PROVIDER_AWSSM,
		adminv1.BrokerProvider_BROKER_PROVIDER_GCPSM,
		adminv1.BrokerProvider_BROKER_PROVIDER_AZUREKV,
	}
	for _, e := range enums {
		s := providerEnumToString(e)
		if got := providerStringToEnum(s); got != e {
			t.Errorf("roundtrip %v -> %q -> %v", e, s, got)
		}
	}
}

func TestNewTenantAdminServer_RequiresAllDeps(t *testing.T) {
	r := &fakeTenantConfigReader{}
	w := &fakeTenantConfigWriter{}
	p := &fakeProbeFactory{}
	au := &fakeAuditor{}
	rl := &fakeReloader{}

	cases := []struct {
		name string
		cfg  TenantAdminConfig
	}{
		{"missing Reader", TenantAdminConfig{}},
		{"missing Writer", TenantAdminConfig{Reader: r}},
		{"missing ProbeFactory", TenantAdminConfig{Reader: r, Writer: w}},
		{"missing Auditor", TenantAdminConfig{Reader: r, Writer: w, ProbeFactory: p}},
		{"missing Reloader", TenantAdminConfig{Reader: r, Writer: w, ProbeFactory: p, Auditor: au}},
		{"missing SecretsService", TenantAdminConfig{Reader: r, Writer: w, ProbeFactory: p, Auditor: au, Reloader: rl}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewTenantAdminServer(tc.cfg); err == nil {
				t.Errorf("%s: expected error", tc.name)
			}
		})
	}
}
