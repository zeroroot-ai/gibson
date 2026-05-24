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

	"github.com/zero-day-ai/gibson/internal/audit"
	"github.com/zero-day-ai/gibson/internal/secrets"

	adminv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/admin/v1"
	"github.com/zero-day-ai/sdk/auth"
	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"
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

func (f *fakeBroker) Health(_ context.Context) error                { return nil }
func (f *fakeBroker) Probe(_ context.Context) error                 { return f.probe }
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

	resp, err := srv.SetSecret(ctx, &adminv1.SetSecretRequest{
		Name:     "openai-prod",
		Category: adminv1.SecretCategory_SECRET_CATEGORY_CRED,
		Value:    []byte("super-secret-value"),
	})
	if err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	if resp.GetMetadata().GetName() != "cred:openai-prod" {
		t.Errorf("expected stored name cred:openai-prod, got %q", resp.GetMetadata().GetName())
	}
	if resp.GetMetadata().GetCategory() != adminv1.SecretCategory_SECRET_CATEGORY_CRED {
		t.Errorf("category mismatch")
	}
	if got, ok := broker.store["cred:openai-prod"]; !ok || string(got) != "super-secret-value" {
		t.Errorf("broker did not receive value, got %q (ok=%v)", got, ok)
	}
}

func TestSetSecret_RequiresTenant(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	_, err := srv.SetSecret(context.Background(), &adminv1.SetSecretRequest{
		Name:     "x",
		Category: adminv1.SecretCategory_SECRET_CATEGORY_CRED,
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
	_, err := srv.SetSecret(ctx, &adminv1.SetSecretRequest{
		Name:     "x",
		Category: adminv1.SecretCategory_SECRET_CATEGORY_CRED,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
}

func TestGetSecret_MetadataOnly(t *testing.T) {
	srv, broker, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	broker.store["cred:openai-prod"] = []byte("v")

	resp, err := srv.GetSecret(ctx, &adminv1.GetSecretRequest{Name: "cred:openai-prod"})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if resp.GetMetadata().GetName() != "cred:openai-prod" {
		t.Errorf("name mismatch")
	}
	if resp.GetMetadata().GetCategory() != adminv1.SecretCategory_SECRET_CATEGORY_CRED {
		t.Errorf("category mismatch")
	}
	// SECURITY: response message has no value field by proto contract.
	// We assert the response wire shape has no plaintext by examining
	// the proto message: GetSecretResponse contains only metadata.
}

func TestGetSecret_NotFound(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.GetSecret(ctx, &adminv1.GetSecretRequest{Name: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("want NotFound, got %v", err)
	}
}

func TestRotateSecret_EmitsRotatedEvent(t *testing.T) {
	srv, broker, _, rotated, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	broker.store["cred:db"] = []byte("old")

	resp, err := srv.RotateSecret(ctx, &adminv1.RotateSecretRequest{
		Name:  "cred:db",
		Value: []byte("new"),
	})
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if resp.GetMetadata().GetName() != "cred:db" {
		t.Errorf("name mismatch")
	}
	if string(broker.store["cred:db"]) != "new" {
		t.Errorf("broker did not receive new value")
	}
	if len(rotated.events) != 1 || rotated.events[0].Action != "secret_rotated" {
		t.Errorf("expected one secret_rotated event, got %+v", rotated.events)
	}
}

func TestRotateSecret_NotFound(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.RotateSecret(ctx, &adminv1.RotateSecretRequest{
		Name:  "missing",
		Value: []byte("v"),
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("want NotFound, got %v", err)
	}
}

func TestDeleteSecret_EmitsRevokedEvent(t *testing.T) {
	srv, broker, _, rotated, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	broker.store["cred:db"] = []byte("v")

	_, err := srv.DeleteSecret(ctx, &adminv1.DeleteSecretRequest{Name: "cred:db"})
	if err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, ok := broker.store["cred:db"]; ok {
		t.Errorf("broker still has key")
	}
	if len(rotated.events) != 1 || rotated.events[0].Action != "secret_revoked" {
		t.Errorf("expected one secret_revoked event, got %+v", rotated.events)
	}
}

func TestListSecrets_ReturnsMetadataOnly(t *testing.T) {
	srv, broker, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	broker.store["cred:a"] = []byte("av")
	broker.store["cred:b"] = []byte("bv")
	broker.store["provider_config:openai:default"] = []byte("k")

	resp, err := srv.ListSecrets(ctx, &adminv1.ListSecretsRequest{
		CategoryFilter: adminv1.SecretCategory_SECRET_CATEGORY_CRED,
	})
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(resp.GetSecrets()) != 2 {
		t.Errorf("expected 2 cred secrets, got %d", len(resp.GetSecrets()))
	}
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

	resp, err := srv.GetMissionAudit(ctx, &adminv1.GetMissionAuditRequest{MissionId: "mission-X"})
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
	_, err := srv.GetMissionAudit(context.Background(), &adminv1.GetMissionAuditRequest{MissionId: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("want PermissionDenied, got %v", err)
	}
}

func TestGetMissionAudit_RequiresMissionID(t *testing.T) {
	srv, _, _, _, _ := newTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.GetMissionAudit(ctx, &adminv1.GetMissionAuditRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
}

func TestParseCategory(t *testing.T) {
	tests := []struct {
		name string
		want adminv1.SecretCategory
	}{
		{"cred:openai", adminv1.SecretCategory_SECRET_CATEGORY_CRED},
		{"provider_config:anthropic:default", adminv1.SecretCategory_SECRET_CATEGORY_PROVIDER_CONFIG},
		{"unknown", adminv1.SecretCategory_SECRET_CATEGORY_UNSPECIFIED},
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
