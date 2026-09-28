// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for runBootstrap / runWithDeps — the core bootstrap flow, exercised
// without live Kubernetes, Zitadel, or FGA.
//
// Test fakes:
//   - fakeTenantGetter: returns a static Tenant object or an error.
//   - fakeIdpClient: captures EnsureHumanUserNoPassword/CreateSetupInviteCode
//     calls, optionally errors.
//   - fakeFgaClient: captures Check/Write calls, optionally errors.
//   - fakeTenantRoleAssigner: captures Assign calls, optionally errors.
package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// ---- fakes ------------------------------------------------------------------

type fakeTenantGetter struct {
	obj *unstructured.Unstructured
	err error
}

func (f *fakeTenantGetter) Get(_ context.Context, _ string, _ metav1.GetOptions, _ ...string) (*unstructured.Unstructured, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.obj, nil
}

// ensureCall records one EnsureHumanUserNoPassword call.
type ensureCall struct {
	OrgID, Email, GivenName, FamilyName string
}

// inviteCall records one CreateSetupInviteCode call.
type inviteCall struct {
	UserID, URLTemplate string
	Send                bool
}

type fakeIdpClient struct {
	ensureUserID string
	ensureErr    error
	ensureCalls  []ensureCall

	inviteCode  string
	inviteErr   error
	inviteCalls []inviteCall

	closeErr error
	closed   bool
}

func (f *fakeIdpClient) EnsureHumanUserNoPassword(_ context.Context, orgID, email, givenName, familyName string) (string, error) {
	f.ensureCalls = append(f.ensureCalls, ensureCall{OrgID: orgID, Email: email, GivenName: givenName, FamilyName: familyName})
	if f.ensureErr != nil {
		return "", f.ensureErr
	}
	return f.ensureUserID, nil
}

func (f *fakeIdpClient) CreateSetupInviteCode(_ context.Context, userID, urlTemplate string, send bool) (string, error) {
	f.inviteCalls = append(f.inviteCalls, inviteCall{UserID: userID, URLTemplate: urlTemplate, Send: send})
	if f.inviteErr != nil {
		return "", f.inviteErr
	}
	return f.inviteCode, nil
}

func (f *fakeIdpClient) Close() error {
	f.closed = true
	return f.closeErr
}

type fakeFgaClient struct {
	checkResult bool
	checkErr    error
	writeErr    error

	checkCalls []authz.Tuple
	writeCalls [][]authz.Tuple
}

func (f *fakeFgaClient) Check(_ context.Context, user, relation, object string) (bool, error) {
	f.checkCalls = append(f.checkCalls, authz.Tuple{User: user, Relation: relation, Object: object})
	if f.checkErr != nil {
		return false, f.checkErr
	}
	return f.checkResult, nil
}

func (f *fakeFgaClient) Write(_ context.Context, tuples []authz.Tuple) error {
	f.writeCalls = append(f.writeCalls, tuples)
	return f.writeErr
}

// fakeTenantRoleAssigner records Assign calls made by runBootstrap in place
// of the old AddTenantMember + FGA Write (ADR-0093).
type fakeTenantRoleAssigner struct {
	err error

	assignCalls []fakeAssignCall
}

type fakeAssignCall struct {
	Tenant tenantrole.Tenant
	UserID string
	Role   tenantrole.Role
}

func (f *fakeTenantRoleAssigner) Assign(_ context.Context, t tenantrole.Tenant, userID string, r tenantrole.Role) error {
	f.assignCalls = append(f.assignCalls, fakeAssignCall{Tenant: t, UserID: userID, Role: r})
	return f.err
}

// ---- helpers ----------------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// makeTenant builds an unstructured Tenant CR with the given name and
// status.zitadelOrgID.
func makeTenant(name, orgID string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetName(name)
	if orgID != "" {
		_ = unstructured.SetNestedField(obj.Object, orgID, "status", "zitadelOrgID")
	}
	return obj
}

// ---- runBootstrap tests ------------------------------------------------------

func TestRunBootstrap_TenantNotFound_FatalError(t *testing.T) {
	tenants := &fakeTenantGetter{err: errors.New("tenants.gibson.zeroroot.ai \"acme\" not found")}
	idpC := &fakeIdpClient{}
	fgaC := &fakeFgaClient{}
	roles := &fakeTenantRoleAssigner{}

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", "", false, tenants, idpC, fgaC, roles)
	if err == nil {
		t.Fatal("expected error when Tenant CR is missing, got nil")
	}
	if len(idpC.ensureCalls) != 0 {
		t.Errorf("expected no IdP calls when tenant lookup fails, got %d", len(idpC.ensureCalls))
	}
	if len(roles.assignCalls) != 0 {
		t.Errorf("expected no role assignment when tenant lookup fails, got %d", len(roles.assignCalls))
	}
}

func TestRunBootstrap_NoZitadelOrgID_FatalError(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "")} // no org id yet
	idpC := &fakeIdpClient{}
	fgaC := &fakeFgaClient{}
	roles := &fakeTenantRoleAssigner{}

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", "", false, tenants, idpC, fgaC, roles)
	if err == nil {
		t.Fatal("expected error when tenant has no zitadelOrgID, got nil")
	}
	if !strings.Contains(err.Error(), "zitadelOrgID") {
		t.Errorf("error = %q, want mention of zitadelOrgID", err.Error())
	}
	if len(idpC.ensureCalls) != 0 {
		t.Errorf("expected no IdP calls when org id is missing, got %d", len(idpC.ensureCalls))
	}
}

func TestRunBootstrap_EnsureHumanUserFails_FatalError_NoPartialTuple(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureErr: errors.New("zitadel unreachable")}
	fgaC := &fakeFgaClient{}
	roles := &fakeTenantRoleAssigner{}

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", "", false, tenants, idpC, fgaC, roles)
	if err == nil {
		t.Fatal("expected error when EnsureHumanUserNoPassword fails, got nil")
	}
	if len(roles.assignCalls) != 0 {
		t.Errorf("expected role assignment not called after EnsureHumanUserNoPassword failure, got %d calls", len(roles.assignCalls))
	}
	if len(fgaC.checkCalls) != 0 {
		t.Errorf("expected no FGA activity after EnsureHumanUserNoPassword failure, got checks=%d",
			len(fgaC.checkCalls))
	}
}

// TestRunBootstrap_AssignFails_FatalError pins ADR-0093: a failed tenant role
// grant is FATAL. Nothing else can make this tenant's Owner, so an install
// with a Zitadel or FGA outage at this exact moment must not report success
// and strand the operator with no way in.
func TestRunBootstrap_AssignFails_FatalError(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: false}
	roles := &fakeTenantRoleAssigner{err: errors.New("zitadel grant failed")}

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", "", false, tenants, idpC, fgaC, roles)
	if err == nil {
		t.Fatal("expected error when the tenant role assignment fails")
	}
	if len(roles.assignCalls) != 1 {
		t.Errorf("expected exactly 1 Assign attempt, got %d", len(roles.assignCalls))
	}
	// The setup link must already have been sent BEFORE Assign runs, so a
	// retry (the FGA tuple is still absent) can repeat both steps rather
	// than silently skip the link forever.
	if len(idpC.inviteCalls) != 1 {
		t.Errorf("expected the setup link to be sent before the failed Assign, got %d invite calls", len(idpC.inviteCalls))
	}
}

func TestRunBootstrap_HappyPath_Emailed_CreatesUserSendsLinkAssignsOwner(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: false}
	roles := &fakeTenantRoleAssigner{}

	result, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "https://app.example.com/", "auth.example.com", false, tenants, idpC, fgaC, roles)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != outcomeBootstrapped {
		t.Errorf("Outcome = %q, want %q", result.Outcome, outcomeBootstrapped)
	}
	if result.OwnerUserID != "user-owner-1" {
		t.Errorf("OwnerUserID = %q, want user-owner-1", result.OwnerUserID)
	}
	if result.SignInPath != "https://app.example.com/login" {
		t.Errorf("SignInPath = %q, want https://app.example.com/login", result.SignInPath)
	}
	if result.SetupLink != "" {
		t.Errorf("SetupLink = %q, want empty on the emailed path", result.SetupLink)
	}

	// EnsureHumanUserNoPassword called with the tenant's org, not the platform org.
	if len(idpC.ensureCalls) != 1 {
		t.Fatalf("expected 1 EnsureHumanUserNoPassword call, got %d", len(idpC.ensureCalls))
	}
	if idpC.ensureCalls[0].OrgID != "org-123" || idpC.ensureCalls[0].Email != "owner@acme.example" {
		t.Errorf("EnsureHumanUserNoPassword call = %+v, want OrgID=org-123 Email=owner@acme.example", idpC.ensureCalls[0])
	}

	// The setup link is emailed (send=true), never returned as a raw code.
	if len(idpC.inviteCalls) != 1 {
		t.Fatalf("expected 1 CreateSetupInviteCode call, got %d", len(idpC.inviteCalls))
	}
	if !idpC.inviteCalls[0].Send {
		t.Error("expected send=true on the non-offline path")
	}
	if idpC.inviteCalls[0].UserID != "user-owner-1" {
		t.Errorf("invite userID = %q, want user-owner-1", idpC.inviteCalls[0].UserID)
	}
	if !strings.HasPrefix(idpC.inviteCalls[0].URLTemplate, "https://auth.example.com/") {
		t.Errorf("invite urlTemplate = %q, want it built from the public host (ZITADEL_EXTERNAL_DOMAIN), never the issuer", idpC.inviteCalls[0].URLTemplate)
	}

	// The tenant role Syncer assigned Owner for the right tenant and user
	// (ADR-0093): Assign writes the Zitadel grant, then copies it into FGA.
	if len(roles.assignCalls) != 1 {
		t.Fatalf("expected 1 Assign call, got %d", len(roles.assignCalls))
	}
	got := roles.assignCalls[0]
	if got.Role != tenantrole.Owner || got.UserID != "user-owner-1" || got.Tenant != (tenantrole.Tenant{ID: "acme", OrgID: "org-123"}) {
		t.Errorf("Assign call = %+v, want Role=Owner UserID=user-owner-1 Tenant={acme org-123}", got)
	}
}

func TestRunBootstrap_HappyPath_Offline_ReturnsRenderedLink(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1", inviteCode: "raw-code-xyz"}
	fgaC := &fakeFgaClient{checkResult: false}
	roles := &fakeTenantRoleAssigner{}

	result, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", "auth.example.com/", true, tenants, idpC, fgaC, roles)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(idpC.inviteCalls) != 1 || idpC.inviteCalls[0].Send {
		t.Fatalf("expected 1 CreateSetupInviteCode call with send=false, got %+v", idpC.inviteCalls)
	}
	wantLink := "https://auth.example.com/ui/v2/login/verify?userId=user-owner-1&code=raw-code-xyz&invite=true&organization=org-123"
	if result.SetupLink != wantLink {
		t.Errorf("SetupLink = %q, want %q", result.SetupLink, wantLink)
	}
}

func TestRunBootstrap_AlreadyOwner_NoOpSuccess_NoDuplicateAssignOrInvite(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	// EnsureHumanUserNoPassword is idempotent by construction — a second run
	// finds the same existing user.
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: true} // tuple already present
	roles := &fakeTenantRoleAssigner{}

	result, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", "", false, tenants, idpC, fgaC, roles)
	if err != nil {
		t.Fatalf("unexpected error on re-run: %v", err)
	}
	if result.Outcome != outcomeAlreadyOwner {
		t.Errorf("Outcome = %q, want %q", result.Outcome, outcomeAlreadyOwner)
	}
	if result.SetupLink != "" {
		t.Errorf("SetupLink = %q, want empty on a re-run — never re-invalidate a link the owner may have used", result.SetupLink)
	}
	if len(roles.assignCalls) != 0 {
		t.Errorf("expected no role assignment on re-run (tuple already present), got %d calls", len(roles.assignCalls))
	}
	if len(idpC.inviteCalls) != 0 {
		t.Errorf("expected no setup-link (re)send on re-run (tuple already present), got %d calls", len(idpC.inviteCalls))
	}
	// The Zitadel find call still happens (idempotent), but Assign does not.
	if len(idpC.ensureCalls) != 1 {
		t.Errorf("expected 1 EnsureHumanUserNoPassword call on re-run, got %d", len(idpC.ensureCalls))
	}
}

func TestRunBootstrap_FgaCheckFails_FatalError(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkErr: errors.New("fga unreachable")}
	roles := &fakeTenantRoleAssigner{}

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", "", false, tenants, idpC, fgaC, roles)
	if err == nil {
		t.Fatal("expected error when FGA Check fails, got nil")
	}
	if len(roles.assignCalls) != 0 {
		t.Errorf("expected no role assignment when Check fails, got %d", len(roles.assignCalls))
	}
}

func TestRunBootstrap_NoPublicURL_EmptySignInPath(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: false}
	roles := &fakeTenantRoleAssigner{}

	result, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", "", false, tenants, idpC, fgaC, roles)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SignInPath != "" {
		t.Errorf("SignInPath = %q, want empty when publicURL unset", result.SignInPath)
	}
}

func TestRunBootstrap_MissingTenantID_FatalError(t *testing.T) {
	_, err := runBootstrap(context.Background(), "", "owner@acme.example", "", "", false, &fakeTenantGetter{}, &fakeIdpClient{}, &fakeFgaClient{}, &fakeTenantRoleAssigner{})
	if err == nil {
		t.Fatal("expected error for empty tenant id")
	}
}

func TestRunBootstrap_MissingOwnerEmail_FatalError(t *testing.T) {
	_, err := runBootstrap(context.Background(), "acme", "", "", "", false, &fakeTenantGetter{}, &fakeIdpClient{}, &fakeFgaClient{}, &fakeTenantRoleAssigner{})
	if err == nil {
		t.Fatal("expected error for empty owner email")
	}
}

// A failure creating the invite code is fatal, and happens BEFORE Assign, so
// a retry (the FGA tuple is still absent) safely repeats the invite.
func TestRunBootstrap_CreateSetupInviteCodeFails_FatalError_BeforeAssign(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1", inviteErr: errors.New("zitadel down")}
	fgaC := &fakeFgaClient{checkResult: false}
	roles := &fakeTenantRoleAssigner{}

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", "", false, tenants, idpC, fgaC, roles)
	if err == nil || !strings.Contains(err.Error(), "create setup invite code") {
		t.Fatalf("want a create-setup-invite-code error, got: %v", err)
	}
	if len(roles.assignCalls) != 0 {
		t.Errorf("expected Assign not to run after a failed invite-code create, got %d calls", len(roles.assignCalls))
	}
}

// ---- parseFlags tests ---------------------------------------------------------

func TestParseFlags_Valid(t *testing.T) {
	flags, err := parseFlags([]string{"-tenant", "acme", "-owner-email", "owner@acme.example"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.TenantID != "acme" || flags.OwnerEmail != "owner@acme.example" {
		t.Errorf("got tenant=%q email=%q", flags.TenantID, flags.OwnerEmail)
	}
	if flags.OfflineSetup {
		t.Error("OfflineSetup should default to false")
	}
	if flags.SetupSecretKey != "setup-link" {
		t.Errorf("SetupSecretKey = %q, want default setup-link", flags.SetupSecretKey)
	}
	if flags.SetupSecretNamespace != "gibson" {
		t.Errorf("SetupSecretNamespace = %q, want default gibson", flags.SetupSecretNamespace)
	}
}

func TestParseFlags_MissingTenant(t *testing.T) {
	_, err := parseFlags([]string{"-owner-email", "owner@acme.example"})
	if err == nil {
		t.Fatal("expected error when -tenant is missing")
	}
}

func TestParseFlags_MissingOwnerEmail(t *testing.T) {
	_, err := parseFlags([]string{"-tenant", "acme"})
	if err == nil {
		t.Fatal("expected error when -owner-email is missing")
	}
}

func TestParseFlags_BlankValues(t *testing.T) {
	_, err := parseFlags([]string{"-tenant", "  ", "-owner-email", "owner@acme.example"})
	if err == nil {
		t.Fatal("expected error when -tenant is blank/whitespace")
	}
}

func TestParseFlags_OfflineRequiresSetupSecret(t *testing.T) {
	_, err := parseFlags([]string{"-tenant", "acme", "-owner-email", "o@a.c", "-offline-setup"})
	if err == nil || !strings.Contains(err.Error(), "-setup-secret is required") {
		t.Fatalf("want a -setup-secret-required error, got: %v", err)
	}
}

func TestParseFlags_OfflineWithSetupSecret_Valid(t *testing.T) {
	flags, err := parseFlags([]string{
		"-tenant", "acme", "-owner-email", "o@a.c",
		"-offline-setup", "-setup-secret", "acme-owner-setup", "-setup-secret-key", "link",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !flags.OfflineSetup || flags.SetupSecret != "acme-owner-setup" || flags.SetupSecretKey != "link" {
		t.Errorf("got %+v", flags)
	}
}

func TestParseFlags_UnknownFlag_ParseErrorWrapped(t *testing.T) {
	_, err := parseFlags([]string{"-bogus-flag", "x"})
	if err == nil {
		t.Fatal("expected error for an unrecognized flag")
	}
	if !strings.Contains(err.Error(), "parse flags") {
		t.Errorf("error = %q, want it wrapped with \"parse flags\"", err.Error())
	}
}

// ---- nestedString tests ------------------------------------------------------

func TestNestedString_Found(t *testing.T) {
	obj := map[string]any{"status": map[string]any{"zitadelOrgID": "org-123"}}
	v, found, err := nestedString(obj, "status", "zitadelOrgID")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || v != "org-123" {
		t.Errorf("got found=%v value=%q, want found=true value=org-123", found, v)
	}
}

func TestNestedString_MissingKey(t *testing.T) {
	v, found, err := nestedString(map[string]any{}, "status", "zitadelOrgID")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found || v != "" {
		t.Errorf("got found=%v value=%q, want found=false value=empty", found, v)
	}
}

func TestNestedString_IntermediateNotMap(t *testing.T) {
	obj := map[string]any{"status": "scalar-not-a-map"}
	v, found, err := nestedString(obj, "status", "zitadelOrgID")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found || v != "" {
		t.Errorf("got found=%v value=%q, want found=false value=empty when an intermediate field is not a map", found, v)
	}
}

func TestNestedString_NonStringLeaf(t *testing.T) {
	obj := map[string]any{"status": map[string]any{"count": 42}}
	v, found, err := nestedString(obj, "status", "count")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found || v != "" {
		t.Errorf("got found=%v value=%q, want found=false value=empty for a non-string leaf", found, v)
	}
}

// ---- loadKubeConfig tests -----------------------------------------------

func TestLoadKubeConfig_NoInClusterConfigNoKubeconfig_ReturnsWrappedError(t *testing.T) {
	// Not running inside a pod (no KUBERNETES_SERVICE_HOST), and KUBECONFIG
	// points at a path that doesn't exist — both branches fail, so this
	// exercises the wrapped-error return without needing a live cluster.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig-for-test")

	_, err := loadKubeConfig()
	if err == nil {
		t.Skip("a valid in-cluster or default kubeconfig was found in this environment; error path not exercised")
	}
	if !strings.Contains(err.Error(), "load kubeconfig") {
		t.Errorf("error = %q, want it wrapped with \"load kubeconfig\"", err.Error())
	}
}

// ---- runWithDeps tests --------------------------------------------------------

func happyKubeLoader() (*rest.Config, error) {
	return &rest.Config{Host: "http://fake-k8s:6443"}, nil
}

func TestRunWithDeps_HappyPath_ReturnsZero_PrintsSignInPath(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: false}
	roles := &fakeTenantRoleAssigner{}

	var stdout bytes.Buffer
	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "https://app.example.com", "auth.example.com",
		false,
		"", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
		func(_ context.Context) (tenantRoleAssigner, error) { return roles, nil },
	)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "https://app.example.com/login") {
		t.Errorf("stdout = %q, want it to contain the sign-in link", stdout.String())
	}
	if !strings.Contains(stdout.String(), "emailed to the owner") {
		t.Errorf("stdout = %q, want the emailed-link notice", stdout.String())
	}
	if !idpC.closed {
		t.Error("expected idp client Close() to be called")
	}
}

func TestRunWithDeps_KubeLoaderError_ReturnsOne(t *testing.T) {
	var stdout bytes.Buffer
	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "", "",
		false,
		"", "setup-link", "gibson",
		func() (*rest.Config, error) { return nil, errors.New("no kubeconfig") },
		func(_ *rest.Config) (TenantGetter, error) { return nil, errors.New("should not be called") },
		func(_ context.Context) (idpClient, error) { return nil, errors.New("should not be called") },
		func(_ context.Context) (fgaClient, error) { return nil, errors.New("should not be called") },
		func(_ context.Context) (tenantRoleAssigner, error) { return nil, errors.New("should not be called") },
	)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestRunWithDeps_TenantProviderError_ReturnsOne(t *testing.T) {
	var stdout bytes.Buffer
	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "", "",
		false,
		"", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return nil, errors.New("dynamic client failed") },
		func(_ context.Context) (idpClient, error) { return nil, errors.New("should not be called") },
		func(_ context.Context) (fgaClient, error) { return nil, errors.New("should not be called") },
		func(_ context.Context) (tenantRoleAssigner, error) { return nil, errors.New("should not be called") },
	)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestRunWithDeps_IdpBuilderError_ReturnsOne(t *testing.T) {
	var stdout bytes.Buffer
	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "", "",
		false,
		"", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return &fakeTenantGetter{}, nil },
		func(_ context.Context) (idpClient, error) { return nil, errors.New("zitadel probe failed") },
		func(_ context.Context) (fgaClient, error) { return nil, errors.New("should not be called") },
		func(_ context.Context) (tenantRoleAssigner, error) { return nil, errors.New("should not be called") },
	)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestRunWithDeps_FgaBuilderError_ReturnsOne_ClosesIdp(t *testing.T) {
	idpC := &fakeIdpClient{}
	var stdout bytes.Buffer
	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "", "",
		false,
		"", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return &fakeTenantGetter{}, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return nil, errors.New("fga dial failed") },
		func(_ context.Context) (tenantRoleAssigner, error) { return nil, errors.New("should not be called") },
	)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !idpC.closed {
		t.Error("expected idp client Close() to be called even when FGA builder fails")
	}
}

func TestRunWithDeps_BootstrapError_ReturnsOne(t *testing.T) {
	tenants := &fakeTenantGetter{err: errors.New("not found")}
	idpC := &fakeIdpClient{}
	fgaC := &fakeFgaClient{}
	roles := &fakeTenantRoleAssigner{}
	var stdout bytes.Buffer

	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "", "",
		false,
		"", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
		func(_ context.Context) (tenantRoleAssigner, error) { return roles, nil },
	)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("expected no stdout output on failure, got %q", stdout.String())
	}
}

func TestRunWithDeps_AlreadyOwner_ReturnsZero_NoPublicURLMessage(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: true}
	roles := &fakeTenantRoleAssigner{}
	var stdout bytes.Buffer

	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "", "",
		false,
		"", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
		func(_ context.Context) (tenantRoleAssigner, error) { return roles, nil },
	)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "GIBSON_PUBLIC_URL not set") {
		t.Errorf("stdout = %q, want fallback message when publicURL unset", stdout.String())
	}
	if strings.Contains(stdout.String(), "setup link") || strings.Contains(stdout.String(), "emailed") {
		t.Errorf("stdout = %q, want no setup-link message on an already-owner re-run", stdout.String())
	}
	if len(fgaC.writeCalls) != 0 {
		t.Errorf("expected no FGA write for already-owner re-run, got %d", len(fgaC.writeCalls))
	}
}

func TestRunWithDeps_Offline_WritesSetupLinkSecret(t *testing.T) {
	orig := setupLinkWriter
	t.Cleanup(func() { setupLinkWriter = orig })
	var wroteNS, wroteName, wroteKey, wroteLink string
	setupLinkWriter = func(_ context.Context, _ *rest.Config, ns, name, key, link string) error {
		wroteNS, wroteName, wroteKey, wroteLink = ns, name, key, link
		return nil
	}

	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1", inviteCode: "raw-code"}
	fgaC := &fakeFgaClient{checkResult: false}
	roles := &fakeTenantRoleAssigner{}
	var stdout bytes.Buffer

	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "", "auth.example.com",
		true,
		"acme-owner-setup", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
		func(_ context.Context) (tenantRoleAssigner, error) { return roles, nil },
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout: %s", code, stdout.String())
	}
	if wroteNS != "gibson" || wroteName != "acme-owner-setup" || wroteKey != "setup-link" || wroteLink == "" {
		t.Errorf("writer got ns=%q name=%q key=%q link-set=%v", wroteNS, wroteName, wroteKey, wroteLink != "")
	}
	if !strings.Contains(stdout.String(), wroteName) {
		t.Error("stdout should name the Secret the link was written to")
	}
}

func TestRunWithDeps_Offline_SetupLinkWriteFailureIsNonFatal(t *testing.T) {
	orig := setupLinkWriter
	t.Cleanup(func() { setupLinkWriter = orig })
	setupLinkWriter = func(context.Context, *rest.Config, string, string, string, string) error {
		return errors.New("apiserver said no")
	}
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	var stdout bytes.Buffer
	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "", "auth.example.com",
		true,
		"acme-owner-setup", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) {
			return &fakeIdpClient{ensureUserID: "u1", inviteCode: "c"}, nil
		},
		func(_ context.Context) (fgaClient, error) { return &fakeFgaClient{}, nil },
		func(_ context.Context) (tenantRoleAssigner, error) { return &fakeTenantRoleAssigner{}, nil },
	)
	if code != 0 {
		t.Fatalf("a failed Secret write must not fail a succeeded bootstrap; exit=%d", code)
	}
}

// A failed tenant role Assign is FATAL (ADR-0093): nothing else can make this
// tenant's Owner, so the run must exit non-zero rather than report success
// with no Owner granted.
func TestRunWithDeps_FailedRoleAssignIsFatal(t *testing.T) {
	origPA := foundingMemberPreAcceptor
	t.Cleanup(func() { foundingMemberPreAcceptor = origPA })
	foundingMemberPreAcceptor = func(context.Context, *rest.Config, string, string, string) (preAcceptOutcome, error) {
		return preAcceptDone, nil
	}

	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	idpC := &fakeIdpClient{ensureUserID: "u1"}
	code := runWithDeps(context.Background(), discardLogger(), &bytes.Buffer{},
		"acme", "owner@acme.example", "", "", false, "", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return &fakeFgaClient{}, nil },
		func(_ context.Context) (tenantRoleAssigner, error) {
			return &fakeTenantRoleAssigner{err: errors.New("gibson project role not found")}, nil
		},
	)
	if code != 1 {
		t.Fatalf("a failed tenant role assign must fail the run, exit=%d, want 1", code)
	}
}

// ---- resolveIdpEnvConfig tests ------------------------------------------

func setResolveEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GIBSON_IDP_ADMIN_ISSUER", "https://app.example.com")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_ID", "client-1")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_SECRET", "secret-1")
	t.Setenv("GIBSON_IDP_ZITADEL_ORG_ID", "org-1")
	t.Setenv("ZITADEL_URL", "http://gibson-zitadel.gibson.svc.cluster.local:8080")
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", "app.example.com")
}

func TestResolveIdpEnvConfig_AllPresent(t *testing.T) {
	setResolveEnv(t)

	cfg, err := resolveIdpEnvConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Issuer != "https://app.example.com" || cfg.ClientID != "client-1" ||
		cfg.ClientSecret != "secret-1" || cfg.ZitadelOrgID != "org-1" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
	if got := cfg.Endpoint.TokenURL(); got != "http://gibson-zitadel.gibson.svc.cluster.local:8080/oauth/v2/token" {
		t.Errorf("token URL = %q, want the fixed path on the in-cluster base (ADR-0092)", got)
	}
	if got := cfg.Endpoint.Host(); got != "app.example.com" {
		t.Errorf("claimed host = %q, want app.example.com", got)
	}
}

// ADR-0092: the endpoint is not optional. Before it, an empty discovery URL
// silently sent every call to the public edge, which rejected the owner
// creation with 403 on staging on 2026-09-23.
func TestResolveIdpEnvConfig_EndpointIsRequired(t *testing.T) {
	setResolveEnv(t)
	t.Setenv("ZITADEL_URL", "")
	if _, err := resolveIdpEnvConfig(); err == nil || !strings.Contains(err.Error(), "ZITADEL_URL") {
		t.Fatalf("want an error naming ZITADEL_URL, got %v", err)
	}
}

// A ported claimed host would make Zitadel stamp the port into the issuer.
func TestResolveIdpEnvConfig_RefusesAPortedHost(t *testing.T) {
	setResolveEnv(t)
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", "app.example.com:443")
	if _, err := resolveIdpEnvConfig(); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("want an error about the port, got %v", err)
	}
}

func TestResolveIdpEnvConfig_AllMissing(t *testing.T) {
	t.Setenv("GIBSON_IDP_ADMIN_ISSUER", "")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_ID", "")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_SECRET", "")
	t.Setenv("GIBSON_IDP_ZITADEL_ORG_ID", "")

	_, err := resolveIdpEnvConfig()
	if err == nil {
		t.Fatal("expected error when all env vars missing, got nil")
	}
}

func TestResolveIdpEnvConfig_PartialMissing(t *testing.T) {
	t.Setenv("GIBSON_IDP_ADMIN_ISSUER", "https://auth.example.com")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_ID", "")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_SECRET", "secret-1")
	t.Setenv("GIBSON_IDP_ZITADEL_ORG_ID", "org-1")

	_, err := resolveIdpEnvConfig()
	if err == nil {
		t.Fatal("expected error when one env var missing, got nil")
	}
	if !strings.Contains(err.Error(), "GIBSON_IDP_ADMIN_CLIENT_ID") {
		t.Errorf("error = %q, want it to name the missing var", err.Error())
	}
}

// ---- resolveFgaEnvConfig tests -------------------------------------------

func TestResolveFgaEnvConfig_AllPresent(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "store-123")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "model-456")

	cfg, err := resolveFgaEnvConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Addr != "http://fga:8080" || cfg.StoreID != "store-123" || cfg.ModelID != "model-456" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
}

func TestResolveFgaEnvConfig_AllMissing(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "")

	_, err := resolveFgaEnvConfig()
	if err == nil {
		t.Fatal("expected error when all env vars missing, got nil")
	}
}

func TestResolveFgaEnvConfig_PartialMissing(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "model-456")

	_, err := resolveFgaEnvConfig()
	if err == nil {
		t.Fatal("expected error when one env var missing, got nil")
	}
	if !strings.Contains(err.Error(), "EXT_AUTHZ_FGA_STORE_ID") {
		t.Errorf("error = %q, want it to name the missing var", err.Error())
	}
}

// errWriter always fails to write — used to exercise runWithDeps' printErr
// branch (a broken stdout must not turn a successful bootstrap into a
// failure).
type errWriter struct{}

func (errWriter) Write(_ []byte) (int, error) { return 0, errors.New("stdout broken") }

func TestRunWithDeps_IdpCloseFails_StillReturnsSuccessCode(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1", closeErr: errors.New("close failed")}
	fgaC := &fakeFgaClient{checkResult: false}
	roles := &fakeTenantRoleAssigner{}
	var stdout bytes.Buffer

	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "", "",
		false,
		"", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
		func(_ context.Context) (tenantRoleAssigner, error) { return roles, nil },
	)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (Close() failure is logged, not fatal)", code)
	}
	if !idpC.closed {
		t.Error("expected Close() to have been called")
	}
}

func TestRunWithDeps_StdoutWriteFails_StillReturnsZero(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: false}
	roles := &fakeTenantRoleAssigner{}

	code := runWithDeps(
		context.Background(),
		discardLogger(),
		errWriter{},
		"acme", "owner@acme.example", "https://app.example.com", "",
		false,
		"", "setup-link", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
		func(_ context.Context) (tenantRoleAssigner, error) { return roles, nil },
	)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (bootstrap succeeded even though stdout write failed)", code)
	}
}

// ---- buildFgaClient tests --------------------------------------------------
//
// authz.NewFgaAuthorizer performs no network I/O at construction (it only
// validates config and builds an HTTP client) — see internal/platform/authz/client.go
// — so buildFgaClient's real construction path is safe to exercise directly.

func TestBuildFgaClient_MissingEnv_ReturnsError(t *testing.T) {
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "")

	_, err := buildFgaClient(context.Background())
	if err == nil {
		t.Fatal("expected error when FGA env vars are missing")
	}
}

func TestBuildFgaClient_ValidEnv_Succeeds(t *testing.T) {
	// FGA store/model IDs must be valid ULIDs for the SDK client constructor.
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga.example:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAV")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAV")

	client, err := buildFgaClient(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestBuildFgaClient_InvalidStoreID_ReturnsWrappedError(t *testing.T) {
	// EXT_AUTHZ_FGA_STORE_ID is non-empty (passes resolveFgaEnvConfig) but not
	// a valid ULID, so the SDK client constructor itself rejects it.
	t.Setenv("EXT_AUTHZ_FGA_ADDR", "http://fga.example:8080")
	t.Setenv("EXT_AUTHZ_FGA_STORE_ID", "not-a-ulid")
	t.Setenv("EXT_AUTHZ_FGA_MODEL_ID", "01ARZ3NDEKTSV4RRFFQ69G5FAV")

	_, err := buildFgaClient(context.Background())
	if err == nil {
		t.Fatal("expected error for an invalid FGA store id")
	}
	if !strings.Contains(err.Error(), "build FGA authorizer") {
		t.Errorf("error = %q, want it wrapped with \"build FGA authorizer\"", err.Error())
	}
}

// ---- buildIdpClient tests ---------------------------------------------------
//
// zitadel.New performs two real HTTP calls (OIDC discovery, then an OAuth2
// client_credentials token fetch) as its startup probe. Both are mockable
// with httptest, so the happy and failure paths are exercised for real
// rather than left at 0% coverage.

// fakeZitadelServer is a Zitadel that selects its instance by header, like
// the real one (zitadelconntest). zitadel.New's startup probe is one token
// request, which must name the instance.
func fakeZitadelServer(t *testing.T) *httptest.Server {
	t.Helper()
	return zitadelconntest.New(t, "", nil).Server
}

// fakeZitadelServerTokenFails answers 500 on every request, so zitadel.New's
// startup probe fails at the token call.
func fakeZitadelServerTokenFails(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// setIdpEnv renders the env a correct chart gives the first-admin Job: the
// fake as the in-cluster connect base, and the fake's instance as the claim.
func setIdpEnv(t *testing.T, connectURL string) {
	t.Helper()
	t.Setenv("GIBSON_IDP_ADMIN_ISSUER", "https://"+zitadelconntest.DefaultDomain)
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_ID", "client-1")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_SECRET", "secret-1")
	t.Setenv("GIBSON_IDP_ZITADEL_ORG_ID", "org-1")
	t.Setenv("ZITADEL_URL", connectURL)
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", zitadelconntest.DefaultDomain)
}

func TestBuildIdpClient_MissingEnv_ReturnsError(t *testing.T) {
	t.Setenv("GIBSON_IDP_ADMIN_ISSUER", "")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_ID", "")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_SECRET", "")
	t.Setenv("GIBSON_IDP_ZITADEL_ORG_ID", "")

	_, err := buildIdpClient(context.Background())
	if err == nil {
		t.Fatal("expected error when IdP env vars are missing")
	}
}

func TestBuildIdpClient_ValidEnvAndReachableZitadel_Succeeds(t *testing.T) {
	srv := fakeZitadelServer(t)
	setIdpEnv(t, srv.URL)

	client, err := buildIdpClient(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if cerr := client.Close(); cerr != nil {
		t.Errorf("unexpected error closing client: %v", cerr)
	}
}

func TestBuildIdpClient_StartupProbeFails_ReturnsWrappedError(t *testing.T) {
	srv := fakeZitadelServerTokenFails(t)
	setIdpEnv(t, srv.URL)

	_, err := buildIdpClient(context.Background())
	if err == nil {
		t.Fatal("expected error when Zitadel startup probe fails")
	}
	if !strings.Contains(err.Error(), "zitadel startup probe failed") {
		t.Errorf("error = %q, want it to mention the startup probe", err.Error())
	}
}

// ---- newTenantGetter tests ---------------------------------------------------
//
// dynamic.NewForConfig only builds a REST client object — it dials no
// network — so newTenantGetter (the real tenantGetterProvider run() wires
// up) is safe to exercise directly without a live cluster; only an actual
// Get/List call on the result would need one.

func TestNewTenantGetter_BuildsGetterFromConfig(t *testing.T) {
	getter, err := newTenantGetter(&rest.Config{Host: "http://fake-k8s:6443"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if getter == nil {
		t.Fatal("expected non-nil TenantGetter")
	}
}

func TestNewTenantGetter_InvalidTLSConfig_ReturnsWrappedError(t *testing.T) {
	cfg := &rest.Config{
		Host: "http://fake-k8s:6443",
		TLSClientConfig: rest.TLSClientConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
	}
	_, err := newTenantGetter(cfg)
	if err == nil {
		t.Fatal("expected error for an unreadable client cert file")
	}
	if !strings.Contains(err.Error(), "dynamic client") {
		t.Errorf("error = %q, want it wrapped with \"dynamic client\"", err.Error())
	}
}

// ---- interface satisfaction compile-time checks --------------------------

var (
	_ TenantGetter = (*fakeTenantGetter)(nil)
	_ idpClient    = (*fakeIdpClient)(nil)
	_ fgaClient    = (*fakeFgaClient)(nil)
)

// --- hosted#202: the offline setup-link Secret ------------------------------
//
// No password is ever written to a Secret (ADR-0093). These tests exercise
// the create-or-update semantics writeOfflineSetupLinkSecret needs: a fresh
// link on first write, and an overwrite on a retry where CreateSetupInviteCode
// already invalidated the previous code on the Zitadel side.

func TestWriteOfflineSetupLinkSecret_CreatesWithLink(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	if err := writeOfflineSetupLinkSecret(context.Background(), cs, "gibson", "acme-owner-setup", "setup-link", "https://auth.example.com/invite?code=abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sec, err := cs.CoreV1().Secrets("gibson").Get(context.Background(), "acme-owner-setup", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	if sec.StringData["setup-link"] != "https://auth.example.com/invite?code=abc" {
		t.Errorf("secret data = %v", sec.StringData)
	}
	if _, hasPassword := sec.StringData["password"]; hasPassword {
		t.Error("no password field may ever be written to this Secret (ADR-0093)")
	}
}

// THE overwrite rule, the mirror image of the old credential Secret's
// never-overwrite rule: CreateSetupInviteCode already invalidated the
// previous code on the Zitadel side, so a stale value in the Secret would be
// a link that looks live but no longer works.
func TestWriteOfflineSetupLinkSecret_OverwritesStaleLink(t *testing.T) {
	cs := k8sfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "acme-owner-setup", Namespace: "gibson"},
		StringData: map[string]string{"setup-link": "https://auth.example.com/invite?code=stale"},
	})
	if err := writeOfflineSetupLinkSecret(context.Background(), cs, "gibson", "acme-owner-setup", "setup-link", "https://auth.example.com/invite?code=fresh"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sec, _ := cs.CoreV1().Secrets("gibson").Get(context.Background(), "acme-owner-setup", metav1.GetOptions{})
	if sec.StringData["setup-link"] != "https://auth.example.com/invite?code=fresh" {
		t.Fatalf("stale link was not overwritten: %v", sec.StringData)
	}
}

func TestWriteOfflineSetupLinkSecret_WrapsCreateError(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	cs.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("etcd is on fire")
	})
	err := writeOfflineSetupLinkSecret(context.Background(), cs, "gibson", "acme-owner-setup", "setup-link", "https://x")
	if err == nil || !strings.Contains(err.Error(), "gibson/acme-owner-setup") {
		t.Fatalf("want a wrapped error naming the secret, got: %v", err)
	}
}

func TestWriteOfflineSetupLinkSecret_WrapsUpdateError(t *testing.T) {
	cs := k8sfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "acme-owner-setup", Namespace: "gibson"},
	})
	cs.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("conflict")
	})
	err := writeOfflineSetupLinkSecret(context.Background(), cs, "gibson", "acme-owner-setup", "setup-link", "https://x")
	if err == nil || !strings.Contains(err.Error(), "gibson/acme-owner-setup") {
		t.Fatalf("want a wrapped update error naming the secret, got: %v", err)
	}
}

// writeOfflineSetupLinkViaConfig: a config the client cannot be built from
// errors early; a buildable config pointing at nothing fails at the API call.
func TestWriteOfflineSetupLinkViaConfig(t *testing.T) {
	if err := writeOfflineSetupLinkViaConfig(context.Background(),
		&rest.Config{Host: "https://127.0.0.1:1", Timeout: 500 * time.Millisecond},
		"gibson", "s", "setup-link", "https://x"); err == nil {
		t.Fatal("expected an error against an unreachable apiserver")
	}
	if err := writeOfflineSetupLinkViaConfig(context.Background(),
		&rest.Config{Host: "://not a url"}, "gibson", "s", "setup-link", "https://x"); err == nil {
		t.Fatal("expected a client-construction error")
	}
}

func TestOwnerProfileName(t *testing.T) {
	g, f := ownerProfileName("admin@selfhosted.example.com")
	if g != "admin" || f != "Owner" {
		t.Errorf("got %q/%q, want admin/Owner", g, f)
	}
	// no local part → falls back to Admin
	g2, _ := ownerProfileName("@example.com")
	if g2 != "Admin" {
		t.Errorf("empty local: got %q, want Admin", g2)
	}
}

func TestSetupLinkURLTemplate_TrimsTrailingSlash(t *testing.T) {
	got := setupLinkURLTemplate("auth.example.com/")
	want := "https://auth.example.com/ui/v2/login/verify?userId={{.UserID}}&code={{.Code}}&invite=true&organization={{.OrgID}}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// gibson#254 fixed the identical bug in the Platform owner's setup link: it
// was built from the in-cluster issuer, which no browser can reach. This
// pins that the link always names the public host with an explicit scheme,
// from a bare host with no scheme of its own (ZITADEL_EXTERNAL_DOMAIN).
func TestSetupLinkURLTemplate_AlwaysStartsWithHTTPSPublicHost(t *testing.T) {
	got := setupLinkURLTemplate("app.selfhosted.example.com")
	if !strings.HasPrefix(got, "https://app.selfhosted.example.com/") {
		t.Fatalf("got %q, want it to start with https://app.selfhosted.example.com/", got)
	}
	if strings.Contains(got, "https://https://") {
		t.Fatalf("got %q, doubled scheme — externalDomain must never already carry one", got)
	}
}

func TestRenderSetupLink_SubstitutesAllThreePlaceholders(t *testing.T) {
	tmpl := setupLinkURLTemplate("auth.example.com")
	got := renderSetupLink(tmpl, "user-1", "org-1", "code-1")
	want := "https://auth.example.com/ui/v2/login/verify?userId=user-1&code=code-1&invite=true&organization=org-1"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// --- the remaining error branches, so the diff gate measures them ----------

func TestRun_InvalidFlags(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	os.Args = []string{"bootstrap-tenant-owner"} // no -tenant
	if code := run(); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
}

// Valid flags, but no reachable cluster: run() must wire everything and fail
// cleanly at the kube loader instead of panicking. Covers the runWithDeps
// argument wiring in run() itself.
func TestRun_ValidFlagsNoCluster(t *testing.T) {
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig-for-test")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	os.Args = []string{"bootstrap-tenant-owner", "-tenant", "acme", "-owner-email", "o@a.c"}
	if code := run(); code != 1 {
		t.Fatalf("exit = %d, want 1 (no cluster reachable)", code)
	}
}
