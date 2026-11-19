// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"github.com/zeroroot-ai/gibson/internal/platform/componentevents"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/pluginadmin/v1"
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

// fakeAuthorizer records FGA tuple writes / deletes.
type fakeAuthorizer struct {
	mu        sync.Mutex
	writes    [][]authz.Tuple
	deletes   [][]authz.Tuple
	failWrite bool
	// failWrites makes the next n writes fail, then writes work again.
	failWrites int
	// failDelete makes every delete fail.
	failDelete bool
	listObjs   map[string][]string // user -> objects
	// stored holds the tuples that ReadTuples answers with. A test seeds the
	// bindings that exist.
	stored []authz.Tuple
}

// ReadTuples answers the stored question: the tuples that match the filter.
func (f *fakeAuthorizer) ReadTuples(_ context.Context, user, relation, object string) ([]authz.Tuple, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []authz.Tuple
	for _, t := range f.stored {
		if t.User == user && t.Relation == relation && t.Object == object {
			out = append(out, t)
		}
	}
	return out, nil
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
	if f.failWrites > 0 {
		f.failWrites--
		return errors.New("write-failure")
	}
	f.writes = append(f.writes, tuples)
	for _, w := range tuples {
		have := false
		for _, t := range f.stored {
			if t == w {
				have = true
			}
		}
		if !have {
			f.stored = append(f.stored, w)
		}
	}
	return nil
}
func (f *fakeAuthorizer) Delete(_ context.Context, tuples []authz.Tuple) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDelete {
		return errors.New("delete-failure")
	}
	f.deletes = append(f.deletes, tuples)
	for _, d := range tuples {
		kept := f.stored[:0:0]
		for _, t := range f.stored {
			if t != d {
				kept = append(kept, t)
			}
		}
		f.stored = kept
	}
	return nil
}

// bind seeds the stored binding of a plugin principal to a declared secret.
func (f *fakeAuthorizer) bind(principal, secret, tenant string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stored = append(f.stored, authz.Tuple{User: principal, Relation: "can_resolve", Object: authz.SecretObject(tenant, secret)})
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

func newPluginsTestServer(t *testing.T) (*PluginsAdminServer, *fakeComponentInstallRegistry, *fakeAuthorizer, *fakeAuditor) {
	t.Helper()
	reg := &fakeComponentInstallRegistry{installs: map[string]ComponentInstallInfo{}}
	az := &fakeAuthorizer{}
	au := &fakeAuditor{}

	srv, err := NewPluginsAdminServer(PluginsAdminConfig{
		Registry:         reg,
		Authorizer:       az,
		BootstrapAuditor: au,
		Events:           &recordingPublisher{},
		Now:              func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewPluginsAdminServer: %v", err)
	}
	return srv, reg, az, au
}

// ---------------------------------------------------------------------------
// Tests — list / get
// ---------------------------------------------------------------------------

func TestListPluginInstalls_FiltersByName(t *testing.T) {
	srv, reg, _, _ := newPluginsTestServer(t)
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
	srv, _, _, _ := newPluginsTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.GetPluginInstall(ctx, &tenantv1.GetPluginInstallRequest{InstallId: "missing"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("want NotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests — bindings edit / revoke
// ---------------------------------------------------------------------------

// TestRevokePluginSecretBinding_DeletesAndAudits: the tuple deleted names the
// FGA user the plugin registered as, verbatim. A chart-deployed plugin enrols
// as plugin_principal:<vendor>, and a tenant admin grants can_resolve to that
// user; a revocation that shaped the user from the install id deleted a tuple
// nobody held (gibson#154).
func TestRevokePluginSecretBinding_DeletesAndAudits(t *testing.T) {
	srv, reg, az, au := newPluginsTestServer(t)
	reg.installs["abc"] = ComponentInstallInfo{InstallID: "abc", TenantID: "acme", Name: "github", PrincipalRef: "plugin_principal:github"}
	az.bind("plugin_principal:github", "cred:db", "acme")
	ctx := ctxWithTenant(t, "acme")

	_, err := srv.RevokePluginSecretBinding(ctx, &tenantv1.RevokePluginSecretBindingRequest{
		InstallId:    "abc",
		DeclaredName: "cred:db",
	})
	if err != nil {
		t.Fatalf("RevokePluginSecretBinding: %v", err)
	}
	if len(az.deletes) != 1 || len(az.deletes[0]) != 1 {
		t.Fatalf("expected 1 tuple delete, got %+v", az.deletes)
	}
	if got := az.deletes[0][0]; got.User != "plugin_principal:github" || got.Relation != "can_resolve" || got.Object != authz.SecretObject("acme", "cred:db") {
		t.Errorf("deleted tuple = %+v, want the install's own principal on the declared secret", got)
	}
	if len(au.events) != 1 || au.events[0].Action != "secret_access_revoked" {
		t.Errorf("expected secret_access_revoked audit, got %+v", au.events)
	}
}

// With no durable audit record, the binding stays (gibson#676).
func TestRevokePluginSecretBinding_NoRecordMeansNoRevoke(t *testing.T) {
	srv, reg, az, au := newPluginsTestServer(t)
	reg.installs["abc"] = ComponentInstallInfo{InstallID: "abc", TenantID: "acme", Name: "github", PrincipalRef: "plugin_principal:github"}
	az.bind("plugin_principal:github", "cred:db", "acme")
	au.recordErr = errors.New("audit store down")

	_, err := srv.RevokePluginSecretBinding(ctxWithTenant(t, "acme"), &tenantv1.RevokePluginSecretBindingRequest{
		InstallId: "abc", DeclaredName: "cred:db",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
	if len(az.deletes) != 0 {
		t.Fatalf("the tuple was deleted with no audit record: %+v", az.deletes)
	}
}

// TestRevokePluginSecretBinding_RefusesAnInstallItCannotAddress: an install
// with no recorded principal predates gibson#154. Deleting a guessed tuple
// and publishing to a guessed channel would report a revocation that never
// happened, so the RPC refuses and nothing is written, published or audited.
func TestRevokePluginSecretBinding_RefusesAnInstallItCannotAddress(t *testing.T) {
	srv, reg, az, au := newPluginsTestServer(t)
	pub := &recordingPublisher{}
	srv.events = pub
	reg.installs["old"] = ComponentInstallInfo{InstallID: "old", TenantID: "acme", Name: "github"}
	ctx := ctxWithTenant(t, "acme")

	_, err := srv.RevokePluginSecretBinding(ctx, &tenantv1.RevokePluginSecretBindingRequest{InstallId: "old", DeclaredName: "cred:db"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("no principal: want FailedPrecondition, got %v", err)
	}
	_, err = srv.RevokePluginSecretBinding(ctx, &tenantv1.RevokePluginSecretBindingRequest{InstallId: "missing", DeclaredName: "cred:db"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown install: want NotFound, got %v", err)
	}
	if len(az.deletes) != 0 || len(pub.events) != 0 || len(au.events) != 0 {
		t.Fatalf("a refused revocation must leave no trace: deletes=%d published=%d audited=%d", len(az.deletes), len(pub.events), len(au.events))
	}
}

func TestEditPluginSecretBinding_WritesThenDeletes(t *testing.T) {
	srv, reg, az, _ := newPluginsTestServer(t)
	reg.installs["i1"] = ComponentInstallInfo{InstallID: "i1", TenantID: "acme", Name: "p", PrincipalRef: "plugin_principal:p"}
	az.stored = []authz.Tuple{{User: "plugin_principal:p", Relation: "can_resolve", Object: authz.SecretObject("acme", "cred:db")}}
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
		t.Fatalf("expected 1 delete + 1 write, got deletes=%d writes=%d", len(az.deletes), len(az.writes))
	}
	if az.deletes[0][0].User != "plugin_principal:p" || az.writes[0][0].User != "plugin_principal:p" {
		t.Errorf("rebind must move the install's own principal: deleted %+v wrote %+v", az.deletes[0], az.writes[0])
	}
	reg.installs["old"] = ComponentInstallInfo{InstallID: "old", TenantID: "acme", Name: "p"}
	_, err = srv.EditPluginSecretBinding(ctx, &tenantv1.EditPluginSecretBindingRequest{InstallId: "old", DeclaredName: "cred:db", NewExistingRef: "cred:db_v2"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("no principal: want FailedPrecondition, got %v", err)
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
		{"missing Authorizer", PluginsAdminConfig{Registry: &fakeComponentInstallRegistry{}}},
		{"missing BootstrapAuditor", PluginsAdminConfig{Registry: &fakeComponentInstallRegistry{}, Authorizer: &fakeAuthorizer{}}},
		{"missing Events", PluginsAdminConfig{Registry: &fakeComponentInstallRegistry{}, Authorizer: &fakeAuthorizer{}, BootstrapAuditor: &fakeAuditor{}}},
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
	srv, _, _, _ := newPluginsTestServer(t)
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.RevokePluginSecretBinding(ctx, &tenantv1.RevokePluginSecretBindingRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("want InvalidArgument, got %v", err)
	}
}

// _ secrets.AuditEvent reference to ensure import retained by the test
// helper compilation.
var _ = secrets.AuditEvent{}

// ListUsersOfType is a security gate in this package; a double that is
// not set up for it must fail the gate loudly rather than answer "nobody".
func (f *fakeAuthorizer) ListUsersOfType(context.Context, string, string, string, string) ([]string, error) {
	return nil, errListUsersOfTypeNotStubbed
}

// recordingPublisher captures component events for assertions (gibson#154).
type recordingPublisher struct {
	events []publishedEvent
	err    error
}

type publishedEvent struct {
	tenant, principal string
	ev                componentevents.Event
}

func (r *recordingPublisher) Publish(_ context.Context, tenant, principal string, ev componentevents.Event) error {
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, publishedEvent{tenant: tenant, principal: principal, ev: ev})
	return nil
}

// TestRevokePluginSecretBinding_TellsTheRunningPlugin is the gibson#154
// fixture: the revocation reaches the plugin's event channel under the
// declared name, before the audit line, and a publish failure is
// Unavailable so the operator retries.
func TestRevokePluginSecretBinding_TellsTheRunningPlugin(t *testing.T) {
	srv, reg, az, au := newPluginsTestServer(t)
	reg.installs["abc"] = ComponentInstallInfo{InstallID: "abc", TenantID: "acme", Name: "github", PrincipalRef: "plugin_principal:github"}
	az.bind("plugin_principal:github", "cred:db", "acme")
	pub := &recordingPublisher{}
	srv.events = pub
	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.RevokePluginSecretBinding(ctx, &tenantv1.RevokePluginSecretBindingRequest{InstallId: "abc", DeclaredName: "cred:db"}); err != nil {
		t.Fatalf("RevokePluginSecretBinding: %v", err)
	}
	if len(pub.events) != 1 {
		t.Fatalf("published %+v", pub.events)
	}
	got := pub.events[0]
	if got.tenant != "acme" || got.principal != "plugin_principal:github" || got.ev.Type != componentevents.TypeSecretAccessRevoked || got.ev.SecretName != "cred:db" || got.ev.Reason == "" || got.ev.OccurredAt.IsZero() {
		t.Fatalf("event = %+v", got)
	}

	srv.events = &recordingPublisher{err: errors.New("redis down")}
	az.bind("plugin_principal:github", "cred:db", "acme")
	_, err := srv.RevokePluginSecretBinding(ctx, &tenantv1.RevokePluginSecretBindingRequest{InstallId: "abc", DeclaredName: "cred:db"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("publish failure must be Unavailable, got %v", err)
	}
	// The record came first (gibson#676). The failed publish adds a failure
	// record, so the trail does not claim a revocation the plugin did not hear.
	if len(au.events) != 3 || au.events[2].Success || au.events[2].Decision != "deny" {
		t.Fatalf("audit events = %+v, want the first revocation and then a record and a failure record", au.events)
	}
}

// TestRevokePluginSecretBinding_AnUnboundNameIsNotFound: a delete of an absent
// tuple is a no-op. A revoke of a name that was never bound is NotFound, with no
// audit record, no delete and no event.
func TestRevokePluginSecretBinding_AnUnboundNameIsNotFound(t *testing.T) {
	srv, reg, az, au := newPluginsTestServer(t)
	reg.installs["abc"] = ComponentInstallInfo{InstallID: "abc", TenantID: "acme", Name: "github", PrincipalRef: "plugin_principal:github"}
	pub := &recordingPublisher{}
	srv.events = pub
	_, err := srv.RevokePluginSecretBinding(ctxWithTenant(t, "acme"), &tenantv1.RevokePluginSecretBindingRequest{InstallId: "abc", DeclaredName: "cred:never"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("a revoke of a name that was never bound: want NotFound, got %v", err)
	}
	if len(az.deletes) != 0 || len(pub.events) != 0 || len(au.events) != 0 {
		t.Fatalf("a refused revoke must leave no trace: deletes=%d published=%d audited=%d", len(az.deletes), len(pub.events), len(au.events))
	}
}

// TestEditPluginSecretBinding_AnUnboundNameIsNotFound: a delete of an absent
// tuple is a no-op, so the edit reads the stored tuple. A name that was never
// bound writes no grant and tells no plugin.
func TestEditPluginSecretBinding_AnUnboundNameIsNotFound(t *testing.T) {
	srv, reg, az, _ := newPluginsTestServer(t)
	reg.installs["i1"] = ComponentInstallInfo{InstallID: "i1", TenantID: "acme", Name: "p", PrincipalRef: "plugin_principal:p"}
	pub := &recordingPublisher{}
	srv.events = pub
	ctx := ctxWithTenant(t, "acme")
	_, err := srv.EditPluginSecretBinding(ctx, &tenantv1.EditPluginSecretBindingRequest{InstallId: "i1", DeclaredName: "cred:never", NewExistingRef: "cred:db_v2"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("an edit of a name that was never bound: want NotFound, got %v", err)
	}
	if len(az.writes) != 0 || len(az.deletes) != 0 || len(pub.events) != 0 {
		t.Fatalf("a refused edit must leave no trace: writes=%d deletes=%d published=%d", len(az.writes), len(az.deletes), len(pub.events))
	}
}

func TestEditPluginSecretBinding_TellsThePluginTheValueMoved(t *testing.T) {
	srv, reg, az, _ := newPluginsTestServer(t)
	reg.installs["i1"] = ComponentInstallInfo{InstallID: "i1", TenantID: "acme", Name: "p", PrincipalRef: "plugin_principal:p"}
	az.stored = []authz.Tuple{{User: "plugin_principal:p", Relation: "can_resolve", Object: authz.SecretObject("acme", "cred:db")}}
	pub := &recordingPublisher{}
	srv.events = pub
	ctx := ctxWithTenant(t, "acme")
	if _, err := srv.EditPluginSecretBinding(ctx, &tenantv1.EditPluginSecretBindingRequest{InstallId: "i1", DeclaredName: "cred:db", NewExistingRef: "cred:db_v2"}); err != nil {
		t.Fatalf("EditPluginSecretBinding: %v", err)
	}
	if len(pub.events) != 1 || pub.events[0].principal != "plugin_principal:p" || pub.events[0].ev.Type != componentevents.TypeSecretRotated || pub.events[0].ev.SecretName != "cred:db" {
		t.Fatalf("published %+v", pub.events)
	}
	srv.events = &recordingPublisher{err: errors.New("redis down")}
	az.bind("plugin_principal:p", "cred:db", "acme")
	if _, err := srv.EditPluginSecretBinding(ctx, &tenantv1.EditPluginSecretBindingRequest{InstallId: "i1", DeclaredName: "cred:db", NewExistingRef: "cred:db_v3"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("publish failure must be Unavailable, got %v", err)
	}
}

func TestNewPluginsAdminServer_RequiresEvents(t *testing.T) {
	cfg := PluginsAdminConfig{Registry: &fakeComponentInstallRegistry{}, Authorizer: &fakeAuthorizer{}, BootstrapAuditor: &fakeAuditor{}}
	if _, err := NewPluginsAdminServer(cfg); err == nil {
		t.Fatal("a plugins admin with no event publisher must not construct")
	}
}

// ---------------------------------------------------------------------------
// Partial failures and their repeat. Each operation can stop after a step, and
// the repeat of the call must finish it. Before this the new read of the stored
// tuple made the repeat of a revoke NotFound, so the plugin never heard of it.
// ---------------------------------------------------------------------------

func newEditFixture(t *testing.T) (*PluginsAdminServer, *fakeAuthorizer, *recordingPublisher, context.Context) {
	t.Helper()
	srv, reg, az, _ := newPluginsTestServer(t)
	reg.installs["i1"] = ComponentInstallInfo{InstallID: "i1", TenantID: "acme", Name: "p", PrincipalRef: "plugin_principal:p"}
	az.bind("plugin_principal:p", "cred:db", "acme")
	pub := &recordingPublisher{}
	srv.events = pub
	return srv, az, pub, ctxWithTenant(t, "acme")
}

func editReq() *tenantv1.EditPluginSecretBindingRequest {
	return &tenantv1.EditPluginSecretBindingRequest{InstallId: "i1", DeclaredName: "cred:db", NewExistingRef: "cred:db_v2"}
}

func isBound(az *fakeAuthorizer, secret string) bool {
	for _, t := range az.stored {
		if t.Object == authz.SecretObject("acme", secret) {
			return true
		}
	}
	return false
}

// The new tuple fails to write: the old binding stays, and the repeat works.
func TestEditPluginSecretBinding_RepeatAfterTheNewWriteFailed(t *testing.T) {
	srv, az, pub, ctx := newEditFixture(t)
	az.failWrites = 1
	if _, err := srv.EditPluginSecretBinding(ctx, editReq()); status.Code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
	if !isBound(az, "cred:db") || isBound(az, "cred:db_v2") || len(pub.events) != 0 {
		t.Fatalf("a failed write must leave the old binding alone: %+v", az.stored)
	}
	if _, err := srv.EditPluginSecretBinding(ctx, editReq()); err != nil {
		t.Fatalf("the repeat: %v", err)
	}
	if isBound(az, "cred:db") || !isBound(az, "cred:db_v2") || len(pub.events) != 1 {
		t.Fatalf("after the repeat: stored %+v, events %d", az.stored, len(pub.events))
	}
}

// The delete of the old tuple fails after the new write: both are bound, and the
// repeat deletes the old one and tells the plugin.
func TestEditPluginSecretBinding_RepeatAfterTheDeleteFailed(t *testing.T) {
	srv, az, pub, ctx := newEditFixture(t)
	az.failDelete = true
	if _, err := srv.EditPluginSecretBinding(ctx, editReq()); status.Code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
	if !isBound(az, "cred:db_v2") {
		t.Fatal("the new tuple is written first")
	}
	az.failDelete = false
	if _, err := srv.EditPluginSecretBinding(ctx, editReq()); err != nil {
		t.Fatalf("the repeat: %v", err)
	}
	if isBound(az, "cred:db") || len(pub.events) != 1 {
		t.Fatalf("after the repeat: stored %+v, events %d", az.stored, len(pub.events))
	}
}

// The publish fails after the delete and the write. The old tuple is gone. The
// repeat must not read NotFound: it sends the event.
func TestEditPluginSecretBinding_RepeatAfterThePublishFailed(t *testing.T) {
	srv, az, pub, ctx := newEditFixture(t)
	srv.events = &recordingPublisher{err: errors.New("redis down")}
	if _, err := srv.EditPluginSecretBinding(ctx, editReq()); status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	if isBound(az, "cred:db") || !isBound(az, "cred:db_v2") {
		t.Fatalf("stored %+v", az.stored)
	}
	srv.events = pub
	if _, err := srv.EditPluginSecretBinding(ctx, editReq()); err != nil {
		t.Fatalf("the repeat after a failed publish must finish the edit: %v", err)
	}
	if len(pub.events) != 1 || pub.events[0].ev.Type != componentevents.TypeSecretRotated {
		t.Fatalf("the repeat must tell the plugin: %+v", pub.events)
	}
}

// The publish fails after the delete of the tuple. The binding is put back, so
// the repeat finds it, deletes it and tells the plugin.
func TestRevokePluginSecretBinding_RepeatAfterThePublishFailed(t *testing.T) {
	srv, reg, az, au := newPluginsTestServer(t)
	reg.installs["abc"] = ComponentInstallInfo{InstallID: "abc", TenantID: "acme", Name: "github", PrincipalRef: "plugin_principal:github"}
	az.bind("plugin_principal:github", "cred:db", "acme")
	srv.events = &recordingPublisher{err: errors.New("redis down")}
	ctx := ctxWithTenant(t, "acme")
	req := &tenantv1.RevokePluginSecretBindingRequest{InstallId: "abc", DeclaredName: "cred:db"}

	if _, err := srv.RevokePluginSecretBinding(ctx, req); status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	if !isBound(az, "cred:db") {
		t.Fatal("a revoke that could not tell the plugin must leave the binding, or the repeat reads NotFound")
	}
	pub := &recordingPublisher{}
	srv.events = pub
	if _, err := srv.RevokePluginSecretBinding(ctx, req); err != nil {
		t.Fatalf("the repeat: %v", err)
	}
	if isBound(az, "cred:db") || len(pub.events) != 1 || pub.events[0].ev.Type != componentevents.TypeSecretAccessRevoked {
		t.Fatalf("after the repeat: stored %+v, events %+v", az.stored, pub.events)
	}
	if len(au.events) < 3 {
		t.Fatalf("audit events = %+v", au.events)
	}
}

// When the binding cannot be put back, the error says the plugin was not told.
func TestRevokePluginSecretBinding_ThePutBackFails(t *testing.T) {
	srv, reg, az, _ := newPluginsTestServer(t)
	reg.installs["abc"] = ComponentInstallInfo{InstallID: "abc", TenantID: "acme", Name: "github", PrincipalRef: "plugin_principal:github"}
	az.bind("plugin_principal:github", "cred:db", "acme")
	srv.events = &recordingPublisher{err: errors.New("redis down")}
	az.failWrites = 1
	_, err := srv.RevokePluginSecretBinding(ctxWithTenant(t, "acme"), &tenantv1.RevokePluginSecretBindingRequest{InstallId: "abc", DeclaredName: "cred:db"})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "could not be put back") {
		t.Fatalf("want Internal that names the put back, got %v", err)
	}
}
