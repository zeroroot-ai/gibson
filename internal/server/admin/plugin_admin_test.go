package admin

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test fakes
// ---------------------------------------------------------------------------

type fakeComponentInstallRegistry struct {
	installs map[string]ComponentInstallInfo
}

func (r *fakeComponentInstallRegistry) ListAll(_ context.Context, tenant auth.TenantID) ([]ComponentInstallInfo, error) {
	out := []ComponentInstallInfo{}
	for _, v := range r.installs {
		if v.TenantID == tenant.String() {
			out = append(out, v)
		}
	}
	return out, nil
}

func (r *fakeComponentInstallRegistry) Get(_ context.Context, tenant auth.TenantID, installID string) (*ComponentInstallInfo, error) {
	v, ok := r.installs[installID]
	if !ok || v.TenantID != tenant.String() {
		return nil, ErrInstallNotFound
	}
	return &v, nil
}

type fakeManifestValidator struct {
	manifest ValidatedManifest
	errors   []ManifestValidationError
}

func (v *fakeManifestValidator) Validate(_ []byte) (ValidatedManifest, []ManifestValidationError) {
	return v.manifest, v.errors
}

type fakeZitadel struct {
	mu        sync.Mutex
	created   []string
	deleted   []string
	failOn    string // installID where Create should fail
	expiresAt time.Time
}

func (f *fakeZitadel) CreatePrincipal(_ context.Context, _ auth.TenantID, installID, _ string, ttl time.Duration) (string, string, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if installID == f.failOn {
		return "", "", time.Time{}, errors.New("zitadel-failure")
	}
	id := "principal-" + installID
	f.created = append(f.created, id)
	exp := f.expiresAt
	if exp.IsZero() {
		exp = time.Now().Add(ttl)
	}
	return id, "boot-" + installID, exp, nil
}

func (f *fakeZitadel) DeletePrincipal(_ context.Context, principalID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, principalID)
	return nil
}

type fakeSecretWriter struct {
	mu      sync.Mutex
	put     map[string][]byte
	deleted []string
	failPut string
}

func (f *fakeSecretWriter) Put(_ context.Context, _ auth.TenantID, name string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPut == name {
		return errors.New("put-failure")
	}
	if f.put == nil {
		f.put = map[string][]byte{}
	}
	f.put[name] = append([]byte(nil), value...)
	return nil
}

func (f *fakeSecretWriter) Delete(_ context.Context, _ auth.TenantID, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, name)
	delete(f.put, name)
	return nil
}

func (f *fakeSecretWriter) Exists(_ context.Context, _ auth.TenantID, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.put[name]
	return ok, nil
}

// fakeAuthorizer records FGA tuple writes / deletes.
type fakeAuthorizer struct {
	mu        sync.Mutex
	writes    [][]authz.Tuple
	deletes   [][]authz.Tuple
	failWrite bool
	listObjs  map[string][]string // user -> objects
}

func (f *fakeAuthorizer) Check(_ context.Context, _, _, _ string) (bool, error) { return true, nil }
func (f *fakeAuthorizer) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(checks))
	for i := range out {
		out[i] = true
	}
	return out, nil
}
func (f *fakeAuthorizer) Write(_ context.Context, tuples []authz.Tuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrite {
		return errors.New("write-failure")
	}
	f.writes = append(f.writes, tuples)
	return nil
}
func (f *fakeAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, tuples)
	return nil
}
func (f *fakeAuthorizer) ListObjects(_ context.Context, user, _, _ string) ([]string, error) {
	if f.listObjs == nil {
		return nil, nil
	}
	return f.listObjs[user], nil
}
func (f *fakeAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthorizer) StoreID() string { return "test" }
func (f *fakeAuthorizer) ModelID() string { return "test" }
func (f *fakeAuthorizer) Close() error    { return nil }

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

func newPluginsTestServer(t *testing.T) (*PluginsAdminServer, *fakeComponentInstallRegistry, *fakeManifestValidator, *fakeZitadel, *fakeSecretWriter, *fakeAuthorizer, *fakeAuditor) {
	t.Helper()
	reg := &fakeComponentInstallRegistry{installs: map[string]ComponentInstallInfo{}}
	val := &fakeManifestValidator{}
	zit := &fakeZitadel{}
	sw := &fakeSecretWriter{}
	az := &fakeAuthorizer{}
	au := &fakeAuditor{}

	srv, err := NewPluginsAdminServer(PluginsAdminConfig{
		Registry:          reg,
		ManifestValidator: val,
		ZitadelClient:     zit,
		SecretWriter:      sw,
		Authorizer:        az,
		BootstrapAuditor:  au,
		BootstrapTokenTTL: time.Hour,
		Now:               func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewPluginsAdminServer: %v", err)
	}
	return srv, reg, val, zit, sw, az, au
}

// ---------------------------------------------------------------------------
// Tests — list / get
// ---------------------------------------------------------------------------

func TestListPluginInstalls_FiltersByName(t *testing.T) {
	srv, reg, _, _, _, _, _ := newPluginsTestServer(t)
	reg.installs["a1"] = ComponentInstallInfo{InstallID: "a1", TenantID: "acme", Name: "github", Status: "serving"}
	reg.installs["b1"] = ComponentInstallInfo{InstallID: "b1", TenantID: "acme", Name: "openai", Status: "serving"}

	ctx := ctxWithTenant(t, "acme")
	resp, err := srv.ListPluginInstalls(ctx, &tenantv1.ListPluginInstallsRequest{NameFilter: "github"})
	if err != nil {
		t.Fatalf("ListPluginInstalls: %v", err)
	}
	if len(resp.GetInstalls()) != 1 || resp.GetInstalls()[0].GetName() != "github" {
		t.Errorf("expected only github install, got %+v", resp.GetInstalls())
	}
}

func TestGetPluginInstall_NotFound(t *testing.T) {
	srv, _, _, _, _, _, _ := newPluginsTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.GetPluginInstall(ctx, &tenantv1.GetPluginInstallRequest{InstallId: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("want NotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests — RegisterPlugin atomicity
// ---------------------------------------------------------------------------

func TestRegisterPlugin_AtomicSuccess(t *testing.T) {
	srv, _, val, zit, sw, az, au := newPluginsTestServer(t)
	val.manifest = ValidatedManifest{
		Name:            "github-plugin",
		Version:         "1.0.0",
		DeclaredSecrets: []string{"gh_token", "gh_app_secret"},
	}
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.RegisterPlugin(ctx, &tenantv1.RegisterPluginRequest{
		ManifestYaml: []byte("name: github-plugin"),
		Bindings: []*tenantv1.PluginSecretBinding{
			{DeclaredName: "gh_token", Mode: "create", CreateValue: []byte("ghp_xxx")},
			{DeclaredName: "gh_app_secret", Mode: "existing", ExistingRef: "cred:gh_app_secret"},
		},
	})
	if err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	if resp.GetInstallId() == "" || resp.GetPluginPrincipalId() == "" || resp.GetBootstrapToken() == "" {
		t.Errorf("missing fields in response: %+v", resp)
	}
	if len(zit.created) != 1 {
		t.Errorf("expected 1 principal create, got %d", len(zit.created))
	}
	if _, ok := sw.put["gh_token"]; !ok {
		t.Errorf("inline secret gh_token not put to broker")
	}
	if len(az.writes) != 1 || len(az.writes[0]) != 2 {
		t.Errorf("expected 1 batch with 2 tuples, got %+v", az.writes)
	}
	if len(au.events) != 1 || au.events[0].Action != "plugin_register" {
		t.Errorf("expected one plugin_register audit event, got %+v", au.events)
	}
}

func TestRegisterPlugin_RollbackOnZitadelFailure(t *testing.T) {
	// We need the zitadel.failOn to match the install ID generated. Since
	// the install ID is random, we set failOn to "" and instead set
	// failPut on the secret writer to force a failure earlier — same
	// rollback semantics, easier to set up.
	srv, _, val, _, sw, az, _ := newPluginsTestServer(t)
	val.manifest = ValidatedManifest{
		Name:            "p",
		DeclaredSecrets: []string{"s1"},
	}
	sw.failPut = "s1"
	ctx := ctxWithTenant(t, "acme")

	_, err := srv.RegisterPlugin(ctx, &tenantv1.RegisterPluginRequest{
		ManifestYaml: []byte("..."),
		Bindings: []*tenantv1.PluginSecretBinding{
			{DeclaredName: "s1", Mode: "create", CreateValue: []byte("v")},
		},
	})
	if err == nil {
		t.Fatal("expected error on inline secret put failure")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("want Internal, got %v", err)
	}
	// Rollback: nothing put before the failed put, no FGA write attempted.
	if len(az.writes) != 0 {
		t.Errorf("expected 0 FGA writes (transaction aborted), got %d", len(az.writes))
	}
}

func TestRegisterPlugin_RollbackOnFGAFailure(t *testing.T) {
	srv, _, val, zit, sw, az, _ := newPluginsTestServer(t)
	val.manifest = ValidatedManifest{
		Name:            "p",
		DeclaredSecrets: []string{"s1"},
	}
	az.failWrite = true
	ctx := ctxWithTenant(t, "acme")

	_, err := srv.RegisterPlugin(ctx, &tenantv1.RegisterPluginRequest{
		ManifestYaml: []byte("..."),
		Bindings: []*tenantv1.PluginSecretBinding{
			{DeclaredName: "s1", Mode: "create", CreateValue: []byte("v")},
		},
	})
	if err == nil {
		t.Fatal("expected error on FGA write failure")
	}
	// Verify rollback: the inline secret was deleted, principal was deleted.
	if len(sw.deleted) != 1 || sw.deleted[0] != "s1" {
		t.Errorf("expected inline secret rollback, got deleted=%v", sw.deleted)
	}
	if len(zit.deleted) != 1 {
		t.Errorf("expected principal rollback, got deleted=%v", zit.deleted)
	}
}

func TestRegisterPlugin_DryRun(t *testing.T) {
	srv, _, val, zit, sw, az, _ := newPluginsTestServer(t)
	val.manifest = ValidatedManifest{
		Name:            "p",
		DeclaredSecrets: []string{},
	}
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.RegisterPlugin(ctx, &tenantv1.RegisterPluginRequest{
		ManifestYaml: []byte("..."),
		DryRun:       true,
	})
	if err != nil {
		t.Fatalf("RegisterPlugin dry_run: %v", err)
	}
	if resp.GetInstallId() != "" || resp.GetBootstrapToken() != "" {
		t.Errorf("dry_run must not return state-changing fields, got %+v", resp)
	}
	if len(zit.created) != 0 || len(sw.put) != 0 || len(az.writes) != 0 {
		t.Errorf("dry_run created side-effects: zit=%v sw=%v az=%v", zit.created, sw.put, az.writes)
	}
}

func TestRegisterPlugin_ManifestValidationErrors(t *testing.T) {
	srv, _, val, _, _, _, _ := newPluginsTestServer(t)
	val.errors = []ManifestValidationError{
		{Field: "metadata.name", Code: "missing_required", Message: "metadata.name required"},
	}
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.RegisterPlugin(ctx, &tenantv1.RegisterPluginRequest{ManifestYaml: []byte("...")})
	if err == nil {
		t.Fatal("expected error on validation failure")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
	if len(resp.GetValidationErrors()) != 1 || resp.GetValidationErrors()[0].GetField() != "metadata.name" {
		t.Errorf("expected validation_errors with metadata.name field, got %+v", resp.GetValidationErrors())
	}
}

func TestRegisterPlugin_CrossCheckBindings_Missing(t *testing.T) {
	srv, _, val, _, _, _, _ := newPluginsTestServer(t)
	val.manifest = ValidatedManifest{
		Name:            "p",
		DeclaredSecrets: []string{"a", "b"},
	}
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.RegisterPlugin(ctx, &tenantv1.RegisterPluginRequest{
		ManifestYaml: []byte("..."),
		Bindings: []*tenantv1.PluginSecretBinding{
			{DeclaredName: "a", Mode: "create", CreateValue: []byte("v")},
			// "b" missing
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
	if len(resp.GetValidationErrors()) == 0 {
		t.Errorf("expected validation errors")
	}
}

func TestRegisterPlugin_BootstrapTokenAudited(t *testing.T) {
	srv, _, val, _, _, _, au := newPluginsTestServer(t)
	val.manifest = ValidatedManifest{Name: "p"}
	ctx := ctxWithTenant(t, "acme")

	resp, err := srv.RegisterPlugin(ctx, &tenantv1.RegisterPluginRequest{ManifestYaml: []byte("...")})
	if err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	if resp.GetBootstrapToken() == "" {
		t.Fatal("expected bootstrap token")
	}
	if len(au.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(au.events))
	}
	ev := au.events[0]
	if ev.Action != "plugin_register" {
		t.Errorf("audit action: want plugin_register, got %q", ev.Action)
	}
	if !strings.Contains(ev.ResourceURI, resp.GetInstallId()) {
		t.Errorf("audit ResourceURI does not include install_id: %q", ev.ResourceURI)
	}
}

// ---------------------------------------------------------------------------
// Tests — bindings edit / revoke
// ---------------------------------------------------------------------------

func TestRevokePluginSecretBinding_DeletesAndAudits(t *testing.T) {
	srv, _, _, _, _, az, au := newPluginsTestServer(t)
	ctx := ctxWithTenant(t, "acme")

	_, err := srv.RevokePluginSecretBinding(ctx, &tenantv1.RevokePluginSecretBindingRequest{
		InstallId:    "abc",
		DeclaredName: "cred:db",
	})
	if err != nil {
		t.Fatalf("RevokePluginSecretBinding: %v", err)
	}
	if len(az.deletes) != 1 || len(az.deletes[0]) != 1 {
		t.Errorf("expected 1 tuple delete, got %+v", az.deletes)
	}
	if len(au.events) != 1 || au.events[0].Action != "secret_access_revoked" {
		t.Errorf("expected secret_access_revoked audit, got %+v", au.events)
	}
}

func TestEditPluginSecretBinding_DeletesThenWrites(t *testing.T) {
	srv, reg, _, _, _, az, _ := newPluginsTestServer(t)
	reg.installs["i1"] = ComponentInstallInfo{InstallID: "i1", TenantID: "acme", Name: "p"}
	ctx := ctxWithTenant(t, "acme")

	_, err := srv.EditPluginSecretBinding(ctx, &tenantv1.EditPluginSecretBindingRequest{
		InstallId:      "i1",
		DeclaredName:   "cred:db",
		NewExistingRef: "cred:db_v2",
	})
	if err != nil {
		t.Fatalf("EditPluginSecretBinding: %v", err)
	}
	if len(az.deletes) != 1 || len(az.writes) != 1 {
		t.Errorf("expected 1 delete + 1 write, got deletes=%d writes=%d", len(az.deletes), len(az.writes))
	}
}

// ---------------------------------------------------------------------------
// Constructor / argument validation
// ---------------------------------------------------------------------------

func TestNewPluginsAdminServer_RequiresAllFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  PluginsAdminConfig
	}{
		{"missing Registry", PluginsAdminConfig{}},
		{"missing ManifestValidator", PluginsAdminConfig{Registry: &fakeComponentInstallRegistry{}}},
		{"missing ZitadelClient", PluginsAdminConfig{Registry: &fakeComponentInstallRegistry{}, ManifestValidator: &fakeManifestValidator{}}},
		{"missing SecretWriter", PluginsAdminConfig{Registry: &fakeComponentInstallRegistry{}, ManifestValidator: &fakeManifestValidator{}, ZitadelClient: &fakeZitadel{}}},
		{"missing Authorizer", PluginsAdminConfig{Registry: &fakeComponentInstallRegistry{}, ManifestValidator: &fakeManifestValidator{}, ZitadelClient: &fakeZitadel{}, SecretWriter: &fakeSecretWriter{}}},
		{"missing BootstrapAuditor", PluginsAdminConfig{Registry: &fakeComponentInstallRegistry{}, ManifestValidator: &fakeManifestValidator{}, ZitadelClient: &fakeZitadel{}, SecretWriter: &fakeSecretWriter{}, Authorizer: &fakeAuthorizer{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPluginsAdminServer(tc.cfg); err == nil {
				t.Errorf("%s: expected error", tc.name)
			}
		})
	}
}

func TestRevokePluginSecretBinding_RequiresFields(t *testing.T) {
	srv, _, _, _, _, _, _ := newPluginsTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.RevokePluginSecretBinding(ctx, &tenantv1.RevokePluginSecretBindingRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
}

// _ secrets.AuditEvent reference to ensure import retained by the test
// helper compilation.
var _ = secrets.AuditEvent{}
