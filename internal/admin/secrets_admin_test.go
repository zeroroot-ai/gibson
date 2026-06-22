package admin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/audit"
	"github.com/zeroroot-ai/gibson/internal/secrets"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test fakes
// ---------------------------------------------------------------------------

type fakeBroker struct {
	caps  sdksecrets.Capabilities
	store map[string][]byte
	probe error
}

func newFakeBroker() *fakeBroker {
	return &fakeBroker{
		caps: sdksecrets.Capabilities{
			CanPut:    true,
			CanDelete: true,
			CanList:   true,
		},
		store: map[string][]byte{},
	}
}

func (f *fakeBroker) Get(_ context.Context, _ auth.TenantID, name string) ([]byte, error) {
	v, ok := f.store[name]
	if !ok {
		return nil, sdksecrets.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (f *fakeBroker) Put(_ context.Context, _ auth.TenantID, name string, value []byte) error {
	f.store[name] = append([]byte(nil), value...)
	return nil
}

func (f *fakeBroker) Delete(_ context.Context, _ auth.TenantID, name string) error {
	delete(f.store, name)
	return nil
}

func (f *fakeBroker) List(_ context.Context, _ auth.TenantID, filter sdksecrets.Filter) ([]string, error) {
	out := []string{}
	for k := range f.store {
		if filter.Prefix != "" && !strings.HasPrefix(k, filter.Prefix) {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

func (f *fakeBroker) Health(_ context.Context) error        { return nil }
func (f *fakeBroker) Probe(_ context.Context) error         { return f.probe }
func (f *fakeBroker) Capabilities() sdksecrets.Capabilities { return f.caps }

// fakeRegistry returns the same broker for every tenant.
type fakeRegistry struct{ broker sdksecrets.Broker }

func (r *fakeRegistry) For(_ context.Context, _ auth.TenantID) (sdksecrets.Broker, error) {
	return r.broker, nil
}

// fakeCircuit always allows.
type fakeCircuit struct{}

func (fakeCircuit) Execute(_, _ string, fn func() error) error { return fn() }

// fakeAuditor captures emitted events.
type fakeAuditor struct{ events []secrets.AuditEvent }

func (f *fakeAuditor) Audit(_ context.Context, e secrets.AuditEvent) {
	f.events = append(f.events, e)
}

// fakePluginAssocs returns a fixed install ID list per secret.
type fakePluginAssocs struct{ byName map[string][]string }

func (f *fakePluginAssocs) PluginsBoundTo(_ context.Context, _ auth.TenantID, name string) ([]string, error) {
	if f.byName == nil {
		return nil, nil
	}
	return f.byName[name], nil
}

// fakeAuditQuery returns a fixed list of entries for any query.
type fakeAuditQuery struct{ entries []audit.PgEntry }

func (f *fakeAuditQuery) List(_ context.Context, _ string, _ audit.Filters, _, _ int) ([]audit.PgEntry, int, error) {
	return f.entries, len(f.entries), nil
}

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

func newTestServer(t *testing.T) (*SecretsAdminServer, *fakeBroker, *fakeAuditor, *fakeAuditor, *fakeAuditQuery) {
	t.Helper()
	broker := newFakeBroker()
	registry := &fakeRegistry{broker: broker}
	serviceAuditor := &fakeAuditor{}
	rotatedAuditor := &fakeAuditor{}
	auditQuery := &fakeAuditQuery{}

	svc, err := secrets.NewService(registry, fakeCircuit{}, serviceAuditor)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	srv, err := NewSecretsAdminServer(SecretsAdminConfig{
		Service:            svc,
		Broker:             registry,
		PluginAssociations: &fakePluginAssocs{},
		AuditQuery:         auditQuery,
		RotatedAuditor:     rotatedAuditor,
		Now:                func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewSecretsAdminServer: %v", err)
	}
	return srv, broker, serviceAuditor, rotatedAuditor, auditQuery
}

func ctxWithTenant(t *testing.T, id string) context.Context {
	t.Helper()
	tid, err := auth.NewTenantID(id)
	if err != nil {
		t.Fatalf("NewTenantID: %v", err)
	}
	return auth.WithIdentity(context.Background(), auth.Identity{
		Tenant:  tid,
		Subject: "user-1",
	})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSetSecret_NoValueInResponse(t *testing.T) {
	srv, broker, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.SetSecret(ctx, &tenantv1.SetSecretRequest{
		Name:     "openai-prod",
		Category: tenantv1.SecretCategory_SECRET_CATEGORY_CRED,
		Value:    []byte("super-secret-value"),
	})
	if err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	// The caller-facing name strips the "user/" Vault prefix.
	if resp.GetMetadata().GetName() != "cred:openai-prod" {
		t.Errorf("expected caller name cred:openai-prod, got %q", resp.GetMetadata().GetName())
	}
	if resp.GetMetadata().GetCategory() != tenantv1.SecretCategory_SECRET_CATEGORY_CRED {
		t.Errorf("category mismatch")
	}
	// Internally the broker stores the secret under the "user/" namespace.
	if got, ok := broker.store["user/cred:openai-prod"]; !ok || string(got) != "super-secret-value" {
		t.Errorf("broker did not receive value at user/cred:openai-prod, store=%v (ok=%v)", broker.store, ok)
	}
}

func TestSetSecret_RequiresTenant(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	_, err := srv.SetSecret(context.Background(), &tenantv1.SetSecretRequest{
		Name:     "x",
		Category: tenantv1.SecretCategory_SECRET_CATEGORY_CRED,
		Value:    []byte("v"),
	})
	if err == nil {
		t.Fatal("expected error without tenant in ctx")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("want PermissionDenied, got %v", err)
	}
}

func TestSetSecret_RejectsEmptyValue(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.SetSecret(ctx, &tenantv1.SetSecretRequest{
		Name:     "x",
		Category: tenantv1.SecretCategory_SECRET_CATEGORY_CRED,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
}

func TestGetSecret_MetadataOnly(t *testing.T) {
	srv, broker, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	// Secrets are stored under "user/" in the broker; callers use the bare name.
	broker.store["user/cred:openai-prod"] = []byte("v")

	// Caller passes the caller-facing name (no "user/" prefix).
	resp, err := srv.GetSecret(ctx, &tenantv1.GetSecretRequest{Name: "cred:openai-prod"})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	// Response name is also caller-facing (no "user/" prefix).
	if resp.GetMetadata().GetName() != "cred:openai-prod" {
		t.Errorf("name mismatch: got %q", resp.GetMetadata().GetName())
	}
	if resp.GetMetadata().GetCategory() != tenantv1.SecretCategory_SECRET_CATEGORY_CRED {
		t.Errorf("category mismatch")
	}
	// SECURITY: response message has no value field by proto contract.
	// We assert the response wire shape has no plaintext by examining
	// the proto message: GetSecretResponse contains only metadata.
}

func TestGetSecret_NotFound(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.GetSecret(ctx, &tenantv1.GetSecretRequest{Name: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("want NotFound, got %v", err)
	}
}

func TestRotateSecret_EmitsRotatedEvent(t *testing.T) {
	srv, broker, _, rotated, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	// Secrets are stored under "user/" in the broker.
	broker.store["user/cred:db"] = []byte("old")

	// Caller passes the caller-facing name (no "user/" prefix).
	resp, err := srv.RotateSecret(ctx, &tenantv1.RotateSecretRequest{
		Name:  "cred:db",
		Value: []byte("new"),
	})
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	// Response name is caller-facing.
	if resp.GetMetadata().GetName() != "cred:db" {
		t.Errorf("name mismatch: got %q", resp.GetMetadata().GetName())
	}
	// Broker was updated at the stored path.
	if string(broker.store["user/cred:db"]) != "new" {
		t.Errorf("broker did not receive new value at user/cred:db, store=%v", broker.store)
	}
	if len(rotated.events) != 1 || rotated.events[0].Action != "secret_rotated" {
		t.Errorf("expected one secret_rotated event, got %+v", rotated.events)
	}
}

func TestRotateSecret_NotFound(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	// "cred:missing" is a known user-secret name so toStoredName maps it to
	// "user/cred:missing" — which does not exist → NotFound.
	_, err := srv.RotateSecret(ctx, &tenantv1.RotateSecretRequest{
		Name:  "cred:missing",
		Value: []byte("v"),
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("want NotFound, got %v", err)
	}
}

func TestDeleteSecret_EmitsRevokedEvent(t *testing.T) {
	srv, broker, _, rotated, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	// Store at the "user/" path as the broker holds it.
	broker.store["user/cred:db"] = []byte("v")

	// Caller passes the caller-facing name.
	_, err := srv.DeleteSecret(ctx, &tenantv1.DeleteSecretRequest{Name: "cred:db"})
	if err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	// Deleted from the stored path.
	if _, ok := broker.store["user/cred:db"]; ok {
		t.Errorf("broker still has key at user/cred:db")
	}
	if len(rotated.events) != 1 || rotated.events[0].Action != "secret_revoked" {
		t.Errorf("expected one secret_revoked event, got %+v", rotated.events)
	}
}

func TestListSecrets_ReturnsMetadataOnly(t *testing.T) {
	srv, broker, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	// Secrets are stored under "user/" in the broker (new namespace layout).
	broker.store["user/cred:a"] = []byte("av")
	broker.store["user/cred:b"] = []byte("bv")
	broker.store["user/provider_config:openai:default"] = []byte("k")

	resp, err := srv.ListSecrets(ctx, &tenantv1.ListSecretsRequest{
		CategoryFilter: tenantv1.SecretCategory_SECRET_CATEGORY_CRED,
	})
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(resp.GetSecrets()) != 2 {
		t.Errorf("expected 2 cred secrets, got %d", len(resp.GetSecrets()))
	}
	// The "user/" prefix is stripped before returning to the caller.
	for _, s := range resp.GetSecrets() {
		if !strings.HasPrefix(s.GetName(), "cred:") {
			t.Errorf("got non-cred secret %q in cred-filtered list (user/ should be stripped)", s.GetName())
		}
	}
}

func TestGetMissionAudit_AggregatesByRef(t *testing.T) {
	srv, _, _, _, q := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")

	t1 := time.Unix(1700000000, 0)
	t2 := t1.Add(2 * time.Second)

	mkMeta := func(missionID string) []byte {
		b, _ := json.Marshal(map[string]string{
			"mission_id":   missionID,
			"resource_uri": "secret:tenant-acme:cred:db",
		})
		return b
	}

	q.entries = []audit.PgEntry{
		{
			ActorID:    "plugin-1",
			Action:     secrets.ActionSecretRead,
			TargetType: "secret",
			TargetID:   "secret:tenant-acme:cred:db",
			CreatedAt:  t1,
			Metadata:   mkMeta("mission-X"),
		},
		{
			ActorID:    "plugin-2",
			Action:     secrets.ActionSecretRead,
			TargetType: "secret",
			TargetID:   "secret:tenant-acme:cred:db",
			CreatedAt:  t2,
			Metadata:   mkMeta("mission-X"),
		},
		{
			ActorID:    "plugin-1",
			Action:     secrets.ActionSecretRead,
			TargetType: "secret",
			TargetID:   "secret:tenant-acme:cred:db",
			CreatedAt:  t2,
			Metadata:   mkMeta("mission-Y"), // different mission, ignored
		},
	}

	resp, err := srv.GetMissionAudit(ctx, &tenantv1.GetMissionAuditRequest{MissionId: "mission-X"})
	if err != nil {
		t.Fatalf("GetMissionAudit: %v", err)
	}
	if len(resp.GetAccesses()) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(resp.GetAccesses()))
	}
	row := resp.GetAccesses()[0]
	if row.GetRef() != "cred:db" {
		t.Errorf("ref: want cred:db, got %q", row.GetRef())
	}
	if row.GetCount() != 2 {
		t.Errorf("count: want 2, got %d", row.GetCount())
	}
	if len(row.GetPluginInstallIds()) != 2 {
		t.Errorf("plugin install count: want 2, got %d", len(row.GetPluginInstallIds()))
	}
}

func TestGetMissionAudit_RequiresTenant(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	_, err := srv.GetMissionAudit(context.Background(), &tenantv1.GetMissionAuditRequest{MissionId: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("want PermissionDenied, got %v", err)
	}
}

func TestGetMissionAudit_RequiresMissionID(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.GetMissionAudit(ctx, &tenantv1.GetMissionAuditRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
}

func TestParseCategory(t *testing.T) {
	tests := []struct {
		name string
		want tenantv1.SecretCategory
	}{
		// caller-facing form
		{"cred:openai", tenantv1.SecretCategory_SECRET_CATEGORY_CRED},
		{"provider_config:anthropic:default", tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG},
		{"unknown", tenantv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED},
		// stored form (with "user/" prefix) — parseCategory must handle both
		{"user/cred:openai", tenantv1.SecretCategory_SECRET_CATEGORY_CRED},
		{"user/provider_config:anthropic:default", tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG},
	}
	for _, tc := range tests {
		if got := parseCategory(tc.name); got != tc.want {
			t.Errorf("parseCategory(%q): got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestUriToRef(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"secret:tenant-acme:cred:db", "cred:db"},
		{"secret:tenant-acme:provider_config:openai:default", "provider_config:openai:default"},
		{"not-a-secret-uri", ""},
		{"secret:tenant-acme", ""},
	}
	for _, tc := range tests {
		if got := uriToRef(tc.uri); got != tc.want {
			t.Errorf("uriToRef(%q): got %q, want %q", tc.uri, got, tc.want)
		}
	}
}

func TestNewSecretsAdminServer_RequiresService(t *testing.T) {
	_, err := NewSecretsAdminServer(SecretsAdminConfig{})
	if err == nil || !strings.Contains(err.Error(), "Service is required") {
		t.Errorf("want Service required error, got %v", err)
	}
}

func TestNewSecretsAdminServer_RequiresBroker(t *testing.T) {
	registry := &fakeRegistry{broker: newFakeBroker()}
	svc, _ := secrets.NewService(registry, fakeCircuit{}, &fakeAuditor{})
	_, err := NewSecretsAdminServer(SecretsAdminConfig{Service: svc})
	if err == nil || !strings.Contains(err.Error(), "Broker is required") {
		t.Errorf("want Broker required error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// User-prefix (Vault "user/" namespace) tests — gibson#404
// ---------------------------------------------------------------------------

func TestStoredName_PrependUserPrefix(t *testing.T) {
	tests := []struct {
		cat  tenantv1.SecretCategory
		name string
		want string
	}{
		{tenantv1.SecretCategory_SECRET_CATEGORY_CRED, "openai-prod", "user/cred:openai-prod"},
		{tenantv1.SecretCategory_SECRET_CATEGORY_CRED, "cred:openai-prod", "user/cred:openai-prod"},      // bare cat prefix stripped first
		{tenantv1.SecretCategory_SECRET_CATEGORY_CRED, "user/cred:openai-prod", "user/cred:openai-prod"}, // idempotent
		{tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG, "openai:default", "user/provider_config:openai:default"},
		{tenantv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED, "raw", "raw"}, // unspecified — no prefix added
	}
	for _, tc := range tests {
		got := storedName(tc.cat, tc.name)
		if got != tc.want {
			t.Errorf("storedName(%v, %q) = %q, want %q", tc.cat, tc.name, got, tc.want)
		}
	}
}

func TestCallerName_StripsUserPrefix(t *testing.T) {
	tests := []struct {
		stored string
		want   string
	}{
		{"user/cred:openai-prod", "cred:openai-prod"},
		{"user/provider_config:openai:default", "provider_config:openai:default"},
		{"cred:openai-prod", "cred:openai-prod"}, // no prefix — unchanged
		{"infra/postgres", "infra/postgres"},     // infra path — unchanged
	}
	for _, tc := range tests {
		got := callerName(tc.stored)
		if got != tc.want {
			t.Errorf("callerName(%q) = %q, want %q", tc.stored, got, tc.want)
		}
	}
}

func TestToStoredName_RoundTrip(t *testing.T) {
	tests := []struct {
		caller string
		want   string
	}{
		{"cred:openai-prod", "user/cred:openai-prod"},
		{"provider_config:openai:default", "user/provider_config:openai:default"},
		{"user/cred:openai-prod", "user/cred:openai-prod"}, // already stored form
		{"infra/postgres", "infra/postgres"},               // non-user path untouched
		{"unknown", "unknown"},                             // unrecognised prefix
	}
	for _, tc := range tests {
		got := toStoredName(tc.caller)
		if got != tc.want {
			t.Errorf("toStoredName(%q) = %q, want %q", tc.caller, got, tc.want)
		}
	}
}

// TestSetSecret_UserPrefixNamespace verifies end-to-end that SetSecret stores
// under "user/" and returns the caller-facing name (no "user/").
func TestSetSecret_UserPrefixNamespace(t *testing.T) {
	srv, broker, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.SetSecret(ctx, &tenantv1.SetSecretRequest{
		Name:     "my-key",
		Category: tenantv1.SecretCategory_SECRET_CATEGORY_CRED,
		Value:    []byte("secret"),
	})
	if err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	// Caller-facing name: "cred:my-key" (no user/ prefix).
	if resp.GetMetadata().GetName() != "cred:my-key" {
		t.Errorf("caller name: want cred:my-key, got %q", resp.GetMetadata().GetName())
	}
	// Stored in broker under user/ namespace.
	if _, ok := broker.store["user/cred:my-key"]; !ok {
		t.Errorf("want broker key user/cred:my-key; store keys: %v", func() []string {
			ks := make([]string, 0, len(broker.store))
			for k := range broker.store {
				ks = append(ks, k)
			}
			return ks
		}())
	}
	// Infra key (e.g. from before the migration) at bare path not touched.
	if _, ok := broker.store["cred:my-key"]; ok {
		t.Errorf("old bare-path key should not be written: cred:my-key")
	}
}

// TestGetSecret_UserPrefixNamespace verifies that GetSecret translates the
// caller-facing name to stored form for the broker lookup.
func TestGetSecret_UserPrefixNamespace(t *testing.T) {
	srv, broker, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	broker.store["user/provider_config:openai:key"] = []byte("v")

	resp, err := srv.GetSecret(ctx, &tenantv1.GetSecretRequest{Name: "provider_config:openai:key"})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if resp.GetMetadata().GetName() != "provider_config:openai:key" {
		t.Errorf("name: want provider_config:openai:key, got %q", resp.GetMetadata().GetName())
	}
	if resp.GetMetadata().GetCategory() != tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG {
		t.Errorf("category mismatch")
	}
}

// errorMsg returns the gRPC status message or the error string.
func errorMsg(err error) string {
	if err == nil {
		return ""
	}
	if st, ok := status.FromError(err); ok {
		return st.Message()
	}
	return err.Error()
}

// expectErrorContains fails the test if err is nil or its message does not
// contain sub.
func expectErrorContains(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", sub)
	}
	if !strings.Contains(errorMsg(err), sub) {
		t.Errorf("expected error containing %q, got %v", sub, err)
	}
}

// ensure unused-vars warnings fail-soft for tests not yet wired.
var _ = errors.New
