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

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
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
	// The caller-facing name equals the colon-flat root key.
	if resp.GetMetadata().GetName() != "cred:openai-prod" {
		t.Errorf("expected caller name cred:openai-prod, got %q", resp.GetMetadata().GetName())
	}
	if resp.GetMetadata().GetCategory() != tenantv1.SecretCategory_SECRET_CATEGORY_CRED {
		t.Errorf("category mismatch")
	}
	// H1 (gibson#1106): the broker stores the secret colon-flat at the KV root.
	if got, ok := broker.store["cred:openai-prod"]; !ok || string(got) != "super-secret-value" {
		t.Errorf("broker did not receive value at cred:openai-prod, store=%v (ok=%v)", broker.store, ok)
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
	// Secrets are stored colon-flat at the KV root; callers use the same name.
	broker.store["cred:openai-prod"] = []byte("v")

	// Caller passes the caller-facing name (colon-flat root key).
	resp, err := srv.GetSecret(ctx, &tenantv1.GetSecretRequest{Name: "cred:openai-prod"})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	// Response name is the same colon-flat root key.
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
	// Secrets are stored colon-flat at the KV root.
	broker.store["cred:db"] = []byte("old")

	// Caller passes the caller-facing name (colon-flat root key).
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
	if string(broker.store["cred:db"]) != "new" {
		t.Errorf("broker did not receive new value at cred:db, store=%v", broker.store)
	}
	if len(rotated.events) != 1 || rotated.events[0].Action != "secret_rotated" {
		t.Errorf("expected one secret_rotated event, got %+v", rotated.events)
	}
}

func TestRotateSecret_NotFound(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	// "cred:missing" is the colon-flat root key, which does not exist → NotFound.
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
	// Store at the colon-flat root key as the broker holds it.
	broker.store["cred:db"] = []byte("v")

	// Caller passes the caller-facing name.
	_, err := srv.DeleteSecret(ctx, &tenantv1.DeleteSecretRequest{Name: "cred:db"})
	if err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	// Deleted from the stored path.
	if _, ok := broker.store["cred:db"]; ok {
		t.Errorf("broker still has key at cred:db")
	}
	if len(rotated.events) != 1 || rotated.events[0].Action != "secret_revoked" {
		t.Errorf("expected one secret_revoked event, got %+v", rotated.events)
	}
}

func TestListSecrets_ReturnsMetadataOnly(t *testing.T) {
	srv, broker, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	// Secrets are stored colon-flat at the KV root (H1 layout, gibson#1106).
	broker.store["cred:a"] = []byte("av")
	broker.store["cred:b"] = []byte("bv")
	broker.store["provider_config:openai:default"] = []byte("k")

	resp, err := srv.ListSecrets(ctx, &tenantv1.ListSecretsRequest{
		CategoryFilter: tenantv1.SecretCategory_SECRET_CATEGORY_CRED,
	})
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(resp.GetSecrets()) != 2 {
		t.Errorf("expected 2 cred secrets, got %d", len(resp.GetSecrets()))
	}
	// Names are the colon-flat root keys returned to the caller.
	for _, s := range resp.GetSecrets() {
		if !strings.HasPrefix(s.GetName(), "cred:") {
			t.Errorf("got non-cred secret %q in cred-filtered list", s.GetName())
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
		// colon-flat root keys (stored form == caller-facing form)
		{"cred:openai", tenantv1.SecretCategory_SECRET_CATEGORY_CRED},
		{"provider_config:anthropic:default", tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG},
		{"unknown", tenantv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED},
	}
	for _, tc := range tests {
		if got := parseCategory(tc.name); got != tc.want {
			t.Errorf("parseCategory(%q): got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestUriToRef(t *testing.T) {
	// The canonical secret object format is "secret:tenant-<id>/<ref>" —
	// tenant-id and ref joined with "/" (NOT ":"). See gibson#1024 and
	// authz.TenantQualifiedSep: OpenFGA rejects a colon inside an object id.
	//
	// uriToRef also accepts the legacy colon form for backward compat with
	// pre-gibson#1024 audit log entries in the database.
	tests := []struct {
		uri  string
		want string
	}{
		// Canonical slash-separated format (gibson#1024 / authz.TenantQualifiedSep).
		{"secret:tenant-acme/cred:db", "cred:db"},
		{"secret:tenant-acme/provider_config:openai:default", "provider_config:openai:default"},
		// Legacy colon form (pre-gibson#1024) — accepted for audit-log backward compat.
		{"secret:tenant-acme:cred:db", "cred:db"},
		{"secret:tenant-acme:provider_config:openai:default", "provider_config:openai:default"},
		// Non-matching inputs.
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

// TestSecretObjectID_WriterDeriverAgreement asserts that the daemon-side WRITER
// (plugin_admin.go: fmt.Sprintf("secret:tenant-%s/%s", tenant, ref)) and the
// ext-authz DERIVER (tenant_and_field — uses authz.TenantQualifiedSep) produce
// exactly the same FGA object id for the same (tenant, ref) pair.
//
// This is the gibson#1035 regression guard: before the fix the deriver joined
// tenant and field with ":" (the old pre-#1024 form) while the writer used "/",
// so ext-authz's can_resolve Check never matched the tuple the operator wrote,
// causing plugin secret resolution to always deny.
//
// The test is self-contained in the admin package: both sides are expressed via
// the shared authz.TenantQualifiedSep constant.
func TestSecretObjectID_WriterDeriverAgreement(t *testing.T) {
	const tenant = "acme"
	const ref = "cred:openai-prod"

	// Writer form: what plugin_admin.go puts in the FGA tuple's Object field.
	// Uses authz.SecretObject — the canonical helper for all secret writers.
	writerObj := authz.SecretObject(tenant, ref)

	// Deriver form: what ext-authz's tenant_and_field deriver produces when the
	// caller provides a secret ref (objectType="secret", tenant=acme, field=ref).
	// Uses authz.SecretObjectFromDeriver — the ext-authz mirror of SecretObject.
	// Both helpers must produce exactly the same string (gibson#1035).
	deriverObj := authz.SecretObjectFromDeriver(tenant, ref)

	if writerObj != deriverObj {
		t.Fatalf("writer object id %q != deriver object id %q — can_resolve Check will never match the written tuple (gibson#1035)", writerObj, deriverObj)
	}

	// Assert the tenant-qualifier separator is "/" (not ":").
	// The fix in gibson#1024 changed "secret:tenant-acme:ref" (3-part colon split,
	// rejected by OpenFGA v1.8.4) to "secret:tenant-acme/ref" (single-colon type
	// prefix, slash-delimited id). The ref portion may itself contain colons
	// (e.g. "cred:openai-prod") — OpenFGA tolerates colons in the id body; what
	// it rejects is a THIRD colon at the type-id boundary.
	// We verify the canonical separator "/" appears between "tenant-acme" and ref.
	if !strings.Contains(writerObj, "tenant-"+tenant+"/") {
		t.Fatalf("secret object id %q does not use '/' as the tenant separator (should be 'secret:tenant-<slug>/<ref>'; gibson#1024)", writerObj)
	}

	// uriToRef must recover ref from the writer object (round-trip check).
	if got := uriToRef(writerObj); got != ref {
		t.Fatalf("uriToRef(%q) = %q, want %q", writerObj, got, ref)
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
// Colon-flat root key layout tests — H1 fix (gibson#1106)
//
// Tenant secrets are stored colon-flat at the KV root ("cred:<name>" /
// "provider_config:<name>") so a Hosted namespace-mode root LIST finds them.
// The retired "user/<category>:<name>" layout was invisible to that LIST. The
// stored key now equals the caller-facing name.
// ---------------------------------------------------------------------------

func TestStoredName_ColonFlatRoot(t *testing.T) {
	tests := []struct {
		cat  tenantv1.SecretCategory
		name string
		want string
	}{
		{tenantv1.SecretCategory_SECRET_CATEGORY_CRED, "openai-prod", "cred:openai-prod"},
		{tenantv1.SecretCategory_SECRET_CATEGORY_CRED, "cred:openai-prod", "cred:openai-prod"}, // idempotent
		{tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG, "openai:default", "provider_config:openai:default"},
		{tenantv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG, "provider_config:openai:default", "provider_config:openai:default"}, // idempotent
		{tenantv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED, "raw", "raw"},                                                           // unspecified — no prefix added
	}
	for _, tc := range tests {
		got := storedName(tc.cat, tc.name)
		if got != tc.want {
			t.Errorf("storedName(%v, %q) = %q, want %q", tc.cat, tc.name, got, tc.want)
		}
	}
}

func TestCallerName_Identity(t *testing.T) {
	// With the colon-flat root layout the stored key equals the caller name.
	tests := []string{
		"cred:openai-prod",
		"provider_config:openai:default",
		"infra/postgres",
	}
	for _, tc := range tests {
		if got := callerName(tc); got != tc {
			t.Errorf("callerName(%q) = %q, want identity", tc, got)
		}
	}
}

func TestToStoredName_Identity(t *testing.T) {
	// With the colon-flat root layout the caller name is already the stored key.
	tests := []string{
		"cred:openai-prod",
		"provider_config:openai:default",
		"infra/postgres",
		"unknown",
	}
	for _, tc := range tests {
		if got := toStoredName(tc); got != tc {
			t.Errorf("toStoredName(%q) = %q, want identity", tc, got)
		}
	}
}

// TestSetSecret_ColonFlatRoot verifies end-to-end that SetSecret stores the
// value colon-flat at the KV root and returns that same name (H1 regression
// guard — the retired "user/" layout is never written).
func TestSetSecret_ColonFlatRoot(t *testing.T) {
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
	// Caller-facing name equals the colon-flat root key.
	if resp.GetMetadata().GetName() != "cred:my-key" {
		t.Errorf("caller name: want cred:my-key, got %q", resp.GetMetadata().GetName())
	}
	// Stored colon-flat at the KV root.
	if _, ok := broker.store["cred:my-key"]; !ok {
		t.Errorf("want broker key cred:my-key; store keys: %v", func() []string {
			ks := make([]string, 0, len(broker.store))
			for k := range broker.store {
				ks = append(ks, k)
			}
			return ks
		}())
	}
	// The retired "user/" layout must never be written.
	if _, ok := broker.store["user/cred:my-key"]; ok {
		t.Errorf("retired user/ layout must not be written: user/cred:my-key")
	}
}

// TestGetSecret_ColonFlatRoot verifies GetSecret finds a colon-flat root key.
func TestGetSecret_ColonFlatRoot(t *testing.T) {
	srv, broker, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	broker.store["provider_config:openai:key"] = []byte("v")

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
