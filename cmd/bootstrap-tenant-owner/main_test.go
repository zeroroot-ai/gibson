// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Tests for runBootstrap / runWithDeps — the core bootstrap flow, exercised
// without live Kubernetes, Zitadel, or FGA.
//
// Test fakes:
//   - fakeTenantGetter: returns a static Tenant object or an error.
//   - fakeIdpClient: captures EnsureHumanUser/AddTenantMember calls, optionally errors.
//   - fakeFgaClient: captures Check/Write calls, optionally errors.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
	"os"
	"time"
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

type fakeIdpClient struct {
	ensureUserID string
	ensureErr    error
	addMemberErr error
	closeErr     error

	ensureCalls []idp.EnsureHumanUserRequest
	addCalls    []idp.TenantMembershipRequest
	closed      bool

	createUserID string
	createErr    error
	createCalls  []idp.CreateHumanUserRequest

	findUserID string
	findErr    error
	findCalls  []string
	findOrgs   []string
	setPwErr   error
	setPwCalls []idp.SetHumanPasswordRequest

	pwChangedAt    time.Time
	pwChangedErr   error
	pwChangedCalls []string
}

func (f *fakeIdpClient) HumanPasswordChangedAt(_ context.Context, userID string) (time.Time, error) {
	f.pwChangedCalls = append(f.pwChangedCalls, userID)
	if f.pwChangedErr != nil {
		return time.Time{}, f.pwChangedErr
	}
	return f.pwChangedAt, nil
}

func (f *fakeIdpClient) FindUserIDByEmailInOrg(_ context.Context, email, orgID string) (string, error) {
	f.findCalls = append(f.findCalls, email)
	f.findOrgs = append(f.findOrgs, orgID)
	if f.findErr != nil {
		return "", f.findErr
	}
	return f.findUserID, nil
}

func (f *fakeIdpClient) SetHumanPassword(_ context.Context, req idp.SetHumanPasswordRequest) error {
	f.setPwCalls = append(f.setPwCalls, req)
	return f.setPwErr
}

func (f *fakeIdpClient) CreateHumanUser(_ context.Context, req idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
	f.createCalls = append(f.createCalls, req)
	if f.createErr != nil {
		return idp.CreateHumanUserResult{}, f.createErr
	}
	return idp.CreateHumanUserResult{UserID: f.createUserID}, nil
}

func (f *fakeIdpClient) EnsureHumanUser(_ context.Context, req idp.EnsureHumanUserRequest) (string, error) {
	f.ensureCalls = append(f.ensureCalls, req)
	if f.ensureErr != nil {
		return "", f.ensureErr
	}
	return f.ensureUserID, nil
}

func (f *fakeIdpClient) AddTenantMember(_ context.Context, req idp.TenantMembershipRequest) error {
	f.addCalls = append(f.addCalls, req)
	return f.addMemberErr
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

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", false, false, tenants, idpC, fgaC)
	if err == nil {
		t.Fatal("expected error when Tenant CR is missing, got nil")
	}
	if len(idpC.ensureCalls) != 0 {
		t.Errorf("expected no IdP calls when tenant lookup fails, got %d", len(idpC.ensureCalls))
	}
	if len(fgaC.writeCalls) != 0 {
		t.Errorf("expected no FGA writes when tenant lookup fails, got %d", len(fgaC.writeCalls))
	}
}

func TestRunBootstrap_NoZitadelOrgID_FatalError(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "")} // no org id yet
	idpC := &fakeIdpClient{}
	fgaC := &fakeFgaClient{}

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", false, false, tenants, idpC, fgaC)
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

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", false, false, tenants, idpC, fgaC)
	if err == nil {
		t.Fatal("expected error when EnsureHumanUser fails, got nil")
	}
	if len(idpC.addCalls) != 0 {
		t.Errorf("expected AddTenantMember not called after EnsureHumanUser failure, got %d calls", len(idpC.addCalls))
	}
	if len(fgaC.checkCalls) != 0 || len(fgaC.writeCalls) != 0 {
		t.Errorf("expected no FGA activity after EnsureHumanUser failure, got checks=%d writes=%d",
			len(fgaC.checkCalls), len(fgaC.writeCalls))
	}
}

// AddTenantMember failure is NON-FATAL: gibson authorises tenant access via the
// FGA owner tuple, not a Zitadel org-member role, so the bootstrap records a
// warning and STILL writes the tuple. The first admin can sign in and own the
// tenant even when the Zitadel org-member grant (e.g. an undefined gibson.owner
// role) does not apply.
func TestRunBootstrap_AddTenantMemberFails_NonFatal_StillWritesTuple(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1", addMemberErr: errors.New("zitadel org add failed")}
	fgaC := &fakeFgaClient{}

	res, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", false, false, tenants, idpC, fgaC)
	if err != nil {
		t.Fatalf("AddTenantMember failure must be non-fatal, got: %v", err)
	}
	if res.MembershipWarning == "" {
		t.Error("a failed org-member grant must surface a warning")
	}
	if len(fgaC.writeCalls) != 1 {
		t.Errorf("the FGA owner tuple must still be written, got %d writes", len(fgaC.writeCalls))
	}
}

func TestRunBootstrap_HappyPath_CreatesUserAndWritesTuple_ReturnsLink(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: false}

	result, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "https://app.example.com/", false, false, tenants, idpC, fgaC)
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

	// EnsureHumanUser called with the tenant's org, not the platform org.
	if len(idpC.ensureCalls) != 1 {
		t.Fatalf("expected 1 EnsureHumanUser call, got %d", len(idpC.ensureCalls))
	}
	if idpC.ensureCalls[0].OrgID != "org-123" || idpC.ensureCalls[0].Email != "owner@acme.example" {
		t.Errorf("EnsureHumanUser call = %+v, want OrgID=org-123 Email=owner@acme.example", idpC.ensureCalls[0])
	}

	// AddTenantMember called with role "owner".
	if len(idpC.addCalls) != 1 {
		t.Fatalf("expected 1 AddTenantMember call, got %d", len(idpC.addCalls))
	}
	if idpC.addCalls[0].Role != "owner" || idpC.addCalls[0].UserID != "user-owner-1" {
		t.Errorf("AddTenantMember call = %+v, want Role=owner UserID=user-owner-1", idpC.addCalls[0])
	}

	// FGA tuple written exactly once, with the right shape.
	if len(fgaC.writeCalls) != 1 || len(fgaC.writeCalls[0]) != 1 {
		t.Fatalf("expected exactly 1 FGA write of 1 tuple, got %+v", fgaC.writeCalls)
	}
	tuple := fgaC.writeCalls[0][0]
	if tuple.User != "user:user-owner-1" {
		t.Errorf("tuple.User = %q, want user:user-owner-1", tuple.User)
	}
	if tuple.Relation != "owner" {
		t.Errorf("tuple.Relation = %q, want owner", tuple.Relation)
	}
	if tuple.Object != "tenant:acme" {
		t.Errorf("tuple.Object = %q, want tenant:acme", tuple.Object)
	}
}

func TestRunBootstrap_AlreadyOwner_NoOpSuccess_NoDuplicateWrite(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	// EnsureHumanUser is idempotent by construction — a second run finds the
	// same existing user.
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: true} // tuple already present

	result, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", false, false, tenants, idpC, fgaC)
	if err != nil {
		t.Fatalf("unexpected error on re-run: %v", err)
	}
	if result.Outcome != outcomeAlreadyOwner {
		t.Errorf("Outcome = %q, want %q", result.Outcome, outcomeAlreadyOwner)
	}
	if len(fgaC.writeCalls) != 0 {
		t.Errorf("expected no FGA write on re-run (tuple already present), got %d writes", len(fgaC.writeCalls))
	}
	// Zitadel calls still happen (both are idempotent finds, not creates) —
	// re-running is safe to repeat exactly like the first run.
	if len(idpC.ensureCalls) != 1 || len(idpC.addCalls) != 1 {
		t.Errorf("expected 1 EnsureHumanUser + 1 AddTenantMember call on re-run, got %d/%d",
			len(idpC.ensureCalls), len(idpC.addCalls))
	}
}

func TestRunBootstrap_FgaCheckFails_FatalError(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkErr: errors.New("fga unreachable")}

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", false, false, tenants, idpC, fgaC)
	if err == nil {
		t.Fatal("expected error when FGA Check fails, got nil")
	}
	if len(fgaC.writeCalls) != 0 {
		t.Errorf("expected no FGA write when Check fails, got %d", len(fgaC.writeCalls))
	}
}

func TestRunBootstrap_FgaWriteFails_FatalError(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: false, writeErr: errors.New("fga write rejected")}

	_, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", false, false, tenants, idpC, fgaC)
	if err == nil {
		t.Fatal("expected error when FGA Write fails, got nil")
	}
}

func TestRunBootstrap_NoPublicURL_EmptySignInPath(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-123")}
	idpC := &fakeIdpClient{ensureUserID: "user-owner-1"}
	fgaC := &fakeFgaClient{checkResult: false}

	result, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", false, false, tenants, idpC, fgaC)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.SignInPath != "" {
		t.Errorf("SignInPath = %q, want empty when publicURL unset", result.SignInPath)
	}
}

func TestRunBootstrap_MissingTenantID_FatalError(t *testing.T) {
	_, err := runBootstrap(context.Background(), "", "owner@acme.example", "", false, false, &fakeTenantGetter{}, &fakeIdpClient{}, &fakeFgaClient{})
	if err == nil {
		t.Fatal("expected error for empty tenant id")
	}
}

func TestRunBootstrap_MissingOwnerEmail_FatalError(t *testing.T) {
	_, err := runBootstrap(context.Background(), "acme", "", "", false, false, &fakeTenantGetter{}, &fakeIdpClient{}, &fakeFgaClient{})
	if err == nil {
		t.Fatal("expected error for empty owner email")
	}
}

// ---- parseFlags tests --------------------------------------------------------

func TestParseFlags_Valid(t *testing.T) {
	flags, err := parseFlags([]string{"-tenant", "acme", "-owner-email", "owner@acme.example"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if flags.TenantID != "acme" || flags.OwnerEmail != "owner@acme.example" {
		t.Errorf("got tenant=%q email=%q", flags.TenantID, flags.OwnerEmail)
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

	var stdout bytes.Buffer
	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "https://app.example.com",
		false,
		"", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
	)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "https://app.example.com/login") {
		t.Errorf("stdout = %q, want it to contain the sign-in link", stdout.String())
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
		"acme", "owner@acme.example", "",
		false,
		"", "gibson",
		func() (*rest.Config, error) { return nil, errors.New("no kubeconfig") },
		func(_ *rest.Config) (TenantGetter, error) { return nil, errors.New("should not be called") },
		func(_ context.Context) (idpClient, error) { return nil, errors.New("should not be called") },
		func(_ context.Context) (fgaClient, error) { return nil, errors.New("should not be called") },
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
		"acme", "owner@acme.example", "",
		false,
		"", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return nil, errors.New("dynamic client failed") },
		func(_ context.Context) (idpClient, error) { return nil, errors.New("should not be called") },
		func(_ context.Context) (fgaClient, error) { return nil, errors.New("should not be called") },
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
		"acme", "owner@acme.example", "",
		false,
		"", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return &fakeTenantGetter{}, nil },
		func(_ context.Context) (idpClient, error) { return nil, errors.New("zitadel probe failed") },
		func(_ context.Context) (fgaClient, error) { return nil, errors.New("should not be called") },
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
		"acme", "owner@acme.example", "",
		false,
		"", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return &fakeTenantGetter{}, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return nil, errors.New("fga dial failed") },
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
	var stdout bytes.Buffer

	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "",
		false,
		"", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
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
	var stdout bytes.Buffer

	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "",
		false,
		"", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
	)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "GIBSON_PUBLIC_URL not set") {
		t.Errorf("stdout = %q, want fallback message when publicURL unset", stdout.String())
	}
	if len(fgaC.writeCalls) != 0 {
		t.Errorf("expected no FGA write for already-owner re-run, got %d", len(fgaC.writeCalls))
	}
}

// ---- resolveIdpEnvConfig tests ------------------------------------------

func TestResolveIdpEnvConfig_AllPresent(t *testing.T) {
	t.Setenv("GIBSON_IDP_ADMIN_ISSUER", "https://auth.example.com")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_ID", "client-1")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_SECRET", "secret-1")
	t.Setenv("GIBSON_IDP_ZITADEL_ORG_ID", "org-1")
	t.Setenv("GIBSON_IDP_ADMIN_DISCOVERY_URL", "https://in-cluster.example")

	cfg, err := resolveIdpEnvConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Issuer != "https://auth.example.com" || cfg.ClientID != "client-1" ||
		cfg.ClientSecret != "secret-1" || cfg.ZitadelOrgID != "org-1" ||
		cfg.DiscoveryURL != "https://in-cluster.example" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
}

func TestResolveIdpEnvConfig_OptionalDiscoveryURLEmpty(t *testing.T) {
	t.Setenv("GIBSON_IDP_ADMIN_ISSUER", "https://auth.example.com")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_ID", "client-1")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_SECRET", "secret-1")
	t.Setenv("GIBSON_IDP_ZITADEL_ORG_ID", "org-1")
	t.Setenv("GIBSON_IDP_ADMIN_DISCOVERY_URL", "")

	cfg, err := resolveIdpEnvConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DiscoveryURL != "" {
		t.Errorf("DiscoveryURL = %q, want empty", cfg.DiscoveryURL)
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
	var stdout bytes.Buffer

	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "",
		false,
		"", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
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

	code := runWithDeps(
		context.Background(),
		discardLogger(),
		errWriter{},
		"acme", "owner@acme.example", "https://app.example.com",
		false,
		"", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
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

// fakeZitadelServer serves a minimal OIDC discovery document and a
// client_credentials token endpoint, matching what zitadel.New's startup
// probe (discoverTokenEndpoint + oauth2 clientcredentials) requires.
func fakeZitadelServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var serverURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": serverURL + "/oauth/v2/token"})
	})
	mux.HandleFunc("/oauth/v2/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	serverURL = srv.URL
	return srv
}

// fakeZitadelServerDiscoveryFails serves a 500 on the discovery endpoint,
// so zitadel.New's startup probe fails before ever reaching the token call.
func fakeZitadelServerDiscoveryFails(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setIdpEnv(t *testing.T, issuer string) {
	t.Helper()
	t.Setenv("GIBSON_IDP_ADMIN_ISSUER", issuer)
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_ID", "client-1")
	t.Setenv("GIBSON_IDP_ADMIN_CLIENT_SECRET", "secret-1")
	t.Setenv("GIBSON_IDP_ZITADEL_ORG_ID", "org-1")
	t.Setenv("GIBSON_IDP_ADMIN_DISCOVERY_URL", "")
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
	srv := fakeZitadelServerDiscoveryFails(t)
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

// --- deploy#1631: the self-hosted first admin -----------------------------

// With -generate-password the owner is created WITH a credential, because a
// vanilla install configures no SMTP and the emailed credential-setup flow
// would strand the operator with an account they can never sign into.
func TestRunBootstrap_GeneratePassword_CreatesWithCredential(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	idpC := &fakeIdpClient{createUserID: "user-1"}
	fgaC := &fakeFgaClient{}

	res, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", true, false, tenants, idpC, fgaC)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(idpC.createCalls) != 1 {
		t.Fatalf("CreateHumanUser calls = %d, want 1", len(idpC.createCalls))
	}
	if len(idpC.ensureCalls) != 0 {
		t.Errorf("EnsureHumanUser must not be used on the generate path, got %d calls", len(idpC.ensureCalls))
	}
	if res.InitialPassword == "" {
		t.Fatal("no initial password returned — the operator has no way in")
	}
	if got := idpC.createCalls[0].Password; got != res.InitialPassword {
		t.Errorf("password sent to the IdP (%q) differs from the one reported to the operator (%q)", got, res.InitialPassword)
	}
	// Sign-in-capable: a vanilla install cannot deliver a verification email,
	// so an unverified account is an account nobody can use.
	if !idpC.createCalls[0].EmailVerified {
		t.Error("EmailVerified=false would leave the account pending an email that cannot be sent")
	}
	if len(res.InitialPassword) < 24 {
		t.Errorf("initial password is only %d chars — too weak for a first admin", len(res.InitialPassword))
	}
}

// THE ONE THAT MATTERS. Re-running the install must not reset a credential the
// operator has already rotated: it falls back to finding the user and reports
// NO password, rather than minting a new one and silently locking them out of
// the one they set.
func TestRunBootstrap_GeneratePassword_RerunDoesNotResetCredential(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	// Re-run is signalled by the credential Secret already existing.
	idpC := &fakeIdpClient{findUserID: "user-1"}
	fgaC := &fakeFgaClient{}

	res, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", true, true, tenants, idpC, fgaC)
	if err != nil {
		t.Fatalf("a re-run must succeed, got: %v", err)
	}
	if res.InitialPassword != "" {
		t.Fatalf("re-run reported a password (%q) — it reset a credential the operator may have rotated", res.InitialPassword)
	}
	if len(idpC.createCalls) != 0 {
		t.Errorf("re-run must not create a user, got %d CreateHumanUser calls", len(idpC.createCalls))
	}
	if len(idpC.setPwCalls) != 0 {
		t.Errorf("re-run must NOT reset the password, got %d SetHumanPassword calls", len(idpC.setPwCalls))
	}
	if len(idpC.findCalls) != 1 {
		t.Errorf("expected the find path on re-run, got %d FindUserIDByEmail calls", len(idpC.findCalls))
	}
	// The owner lives in the TENANT org, not the daemon's admin org. Resolving
	// in the admin org returned ErrNotFound and stranded every re-run and every
	// post-upgrade hook (gibson#1560). The resolve MUST be scoped to the tenant
	// org from the Tenant CR (here "org-1").
	if len(idpC.findOrgs) != 1 || idpC.findOrgs[0] != "org-1" {
		t.Errorf("re-run must resolve the owner in the tenant org, got findOrgs=%v want [org-1]", idpC.findOrgs)
	}
	if res.OwnerUserID != "user-1" {
		t.Errorf("OwnerUserID = %q, want the existing user", res.OwnerUserID)
	}
}

// First setup where the invitation flow already created the owner user: activate
// it by setting the generated password, and DO report the credential.
func TestRunBootstrap_GeneratePassword_ActivatesInvitedOwner(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	idpC := &fakeIdpClient{createErr: idp.ErrAlreadyExists, findUserID: "invited-user"}
	fgaC := &fakeFgaClient{}

	res, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", true, false, tenants, idpC, fgaC)
	if err != nil {
		t.Fatalf("activating an invited owner must succeed, got: %v", err)
	}
	if len(idpC.setPwCalls) != 1 {
		t.Fatalf("want one SetHumanPassword to activate the invited owner, got %d", len(idpC.setPwCalls))
	}
	if res.InitialPassword == "" {
		t.Fatal("activation must report the generated credential so it reaches the Secret")
	}
	if idpC.setPwCalls[0].Password != res.InitialPassword {
		t.Errorf("password set on the IdP (%q) differs from the one reported (%q)", idpC.setPwCalls[0].Password, res.InitialPassword)
	}
	if res.OwnerUserID != "invited-user" {
		t.Errorf("OwnerUserID = %q, want the resolved invited user", res.OwnerUserID)
	}
}

// Without the flag nothing changes: the SaaS/invitation path is untouched.
func TestRunBootstrap_WithoutGeneratePassword_UsesInvitationFlow(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	idpC := &fakeIdpClient{ensureUserID: "user-1"}
	fgaC := &fakeFgaClient{}

	res, err := runBootstrap(context.Background(), "acme", "owner@acme.example", "", false, false, tenants, idpC, fgaC)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(idpC.createCalls) != 0 {
		t.Errorf("CreateHumanUser must not be called without -generate-password, got %d", len(idpC.createCalls))
	}
	if res.InitialPassword != "" {
		t.Errorf("no credential should be reported on the invitation path, got %q", res.InitialPassword)
	}
}

// Two runs must not produce the same credential.
func TestGenerateInitialPassword_IsRandomAndStrong(t *testing.T) {
	a, err := generateInitialPassword()
	if err != nil {
		t.Fatal(err)
	}
	b, err := generateInitialPassword()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two generated passwords are identical — not random")
	}
	if len(a) < 24 {
		t.Errorf("password length %d is too short", len(a))
	}
}

// --- credential Secret: create-only, and actually exercised ---------------

func TestWriteCredentialSecret_CreatesWithRotateInstruction(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	if err := writeCredentialSecret(context.Background(), cs, "gibson", "gibson-first-admin", "a@b.c", "pw-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sec, err := cs.CoreV1().Secrets("gibson").Get(context.Background(), "gibson-first-admin", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	if sec.StringData["username"] != "a@b.c" || sec.StringData["password"] != "pw-1" {
		t.Errorf("secret data = %v", sec.StringData)
	}
	if sec.Annotations["gibson.zeroroot.ai/rotate-me"] == "" {
		t.Error("the rotate-me instruction is the operator-facing contract; it must be present")
	}
}

// THE create-only rule: a pre-existing Secret is success and is NOT touched.
// Overwriting would hand back a password the operator may have replaced.
func TestWriteCredentialSecret_NeverOverwrites(t *testing.T) {
	cs := k8sfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "gibson-first-admin", Namespace: "gibson"},
		StringData: map[string]string{"password": "rotated-by-operator"},
	})
	if err := writeCredentialSecret(context.Background(), cs, "gibson", "gibson-first-admin", "a@b.c", "new-pw"); err != nil {
		t.Fatalf("AlreadyExists must be success, got: %v", err)
	}
	sec, _ := cs.CoreV1().Secrets("gibson").Get(context.Background(), "gibson-first-admin", metav1.GetOptions{})
	if sec.StringData["password"] != "rotated-by-operator" {
		t.Fatalf("existing credential was overwritten: %v", sec.StringData)
	}
}

// The full wiring: a generated credential flows from runBootstrap through the
// injected writer, and a writer failure is non-fatal — the bootstrap already
// succeeded and the password is in the Job output.
func TestRunWithDeps_WritesCredentialSecret(t *testing.T) {
	orig := credentialWriter
	t.Cleanup(func() { credentialWriter = orig })
	var wroteNS, wroteName, wrotePw string
	credentialWriter = func(_ context.Context, _ *rest.Config, ns, name, _, pw string) error {
		wroteNS, wroteName, wrotePw = ns, name, pw
		return nil
	}
	origCheck := credentialChecker
	t.Cleanup(func() { credentialChecker = origCheck })
	credentialChecker = func(context.Context, *rest.Config, string, string) (bool, error) { return false, nil }

	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	idpC := &fakeIdpClient{createUserID: "user-1"}
	fgaC := &fakeFgaClient{}
	var stdout bytes.Buffer
	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "https://app.example.com",
		true,
		"gibson-first-admin", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return fgaC, nil },
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stdout: %s", code, stdout.String())
	}
	if wroteNS != "gibson" || wroteName != "gibson-first-admin" || wrotePw == "" {
		t.Errorf("writer got ns=%q name=%q pw-set=%v", wroteNS, wroteName, wrotePw != "")
	}
	if !strings.Contains(stdout.String(), wrotePw) {
		t.Error("the password surfaced to the operator must be the one written to the Secret")
	}
}

func TestRunWithDeps_CredentialWriteFailureIsNonFatal(t *testing.T) {
	orig := credentialWriter
	t.Cleanup(func() { credentialWriter = orig })
	credentialWriter = func(context.Context, *rest.Config, string, string, string, string) error {
		return errors.New("apiserver said no")
	}
	origCheck := credentialChecker
	t.Cleanup(func() { credentialChecker = origCheck })
	credentialChecker = func(context.Context, *rest.Config, string, string) (bool, error) { return false, nil }
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	var stdout bytes.Buffer
	code := runWithDeps(
		context.Background(),
		discardLogger(),
		&stdout,
		"acme", "owner@acme.example", "",
		true,
		"gibson-first-admin", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return &fakeIdpClient{createUserID: "u1"}, nil },
		func(_ context.Context) (fgaClient, error) { return &fakeFgaClient{}, nil },
	)
	if code != 0 {
		t.Fatalf("a failed Secret write must not fail a succeeded bootstrap; exit=%d", code)
	}
	if !strings.Contains(stdout.String(), "initial admin password:") {
		t.Error("with the Secret write failed, stdout is the only copy — it must still print")
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

func TestRunBootstrap_GeneratePassword_RandFailure(t *testing.T) {
	orig := randRead
	t.Cleanup(func() { randRead = orig })
	randRead = func([]byte) (int, error) { return 0, errors.New("entropy exhausted") }

	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	_, err := runBootstrap(context.Background(), "acme", "o@a.c", "", true, false, tenants, &fakeIdpClient{}, &fakeFgaClient{})
	if err == nil || !strings.Contains(err.Error(), "generate initial password") {
		t.Fatalf("want a generate-password error, got: %v", err)
	}
}

// ErrAlreadyExists then the find path ALSO fails: surfaced, not swallowed.
func TestRunBootstrap_RerunFindFailure(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	idpC := &fakeIdpClient{createErr: idp.ErrAlreadyExists, findErr: errors.New("zitadel down")}
	_, err := runBootstrap(context.Background(), "acme", "o@a.c", "", true, false, tenants, idpC, &fakeFgaClient{})
	if err == nil || !strings.Contains(err.Error(), "resolve existing owner") {
		t.Fatalf("want resolve-existing error, got: %v", err)
	}
}

// A non-AlreadyExists create failure is fatal.
func TestRunBootstrap_CreateFailure(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	idpC := &fakeIdpClient{createErr: errors.New("500 from zitadel")}
	_, err := runBootstrap(context.Background(), "acme", "o@a.c", "", true, false, tenants, idpC, &fakeFgaClient{})
	if err == nil || !strings.Contains(err.Error(), "create owner Zitadel user") {
		t.Fatalf("want create-owner error, got: %v", err)
	}
}

// The Create error is wrapped with the namespace/name it failed on.
func TestWriteCredentialSecret_WrapsCreateError(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	cs.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("etcd is on fire")
	})
	err := writeCredentialSecret(context.Background(), cs, "gibson", "gibson-first-admin", "a@b.c", "pw")
	if err == nil || !strings.Contains(err.Error(), "gibson/gibson-first-admin") {
		t.Fatalf("want a wrapped error naming the secret, got: %v", err)
	}
}

// writeCredentialViaConfig: a config the client cannot be built from errors
// early; a buildable config pointing at nothing fails at the Create call.
func TestWriteCredentialViaConfig(t *testing.T) {
	if err := writeCredentialViaConfig(context.Background(),
		&rest.Config{Host: "https://127.0.0.1:1", Timeout: 500 * time.Millisecond},
		"gibson", "s", "e", "p"); err == nil {
		t.Fatal("expected an error against an unreachable apiserver")
	}
	if err := writeCredentialViaConfig(context.Background(),
		&rest.Config{Host: "://not a url"}, "gibson", "s", "e", "p"); err == nil {
		t.Fatal("expected a client-construction error")
	}
}

func TestCredentialExists(t *testing.T) {
	ctx := context.Background()
	// present
	cs := k8sfake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "gibson-first-admin", Namespace: "gibson"},
	})
	if ok, err := credentialExists(ctx, cs, "gibson", "gibson-first-admin"); err != nil || !ok {
		t.Fatalf("present: got ok=%v err=%v, want true,nil", ok, err)
	}
	// absent
	empty := k8sfake.NewSimpleClientset()
	if ok, err := credentialExists(ctx, empty, "gibson", "gibson-first-admin"); err != nil || ok {
		t.Fatalf("absent: got ok=%v err=%v, want false,nil", ok, err)
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

// Re-run (credential exists) but resolving the owner fails → surfaced.
func TestRunBootstrap_RerunResolveFailure(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	idpC := &fakeIdpClient{findErr: errors.New("zitadel down")}
	_, err := runBootstrap(context.Background(), "acme", "o@a.c", "", true, true, tenants, idpC, &fakeFgaClient{})
	if err == nil || !strings.Contains(err.Error(), "resolve existing owner") {
		t.Fatalf("want resolve-existing error, got: %v", err)
	}
}

// First setup, owner already exists (invited), but SetHumanPassword fails → surfaced.
func TestRunBootstrap_ActivateExistingOwner_SetPasswordFails(t *testing.T) {
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	idpC := &fakeIdpClient{createErr: idp.ErrAlreadyExists, findUserID: "u-invited", setPwErr: errors.New("policy rejected")}
	_, err := runBootstrap(context.Background(), "acme", "o@a.c", "", true, false, tenants, idpC, &fakeFgaClient{})
	if err == nil || !strings.Contains(err.Error(), "activate existing owner with a password") {
		t.Fatalf("want activation error, got: %v", err)
	}
}

// credentialExists surfaces a non-NotFound get error rather than reporting "absent".
func TestCredentialExists_GetError(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	cs.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver exploded")
	})
	if _, err := credentialExists(context.Background(), cs, "gibson", "gibson-first-admin"); err == nil {
		t.Fatal("want the get error surfaced, not swallowed as absent")
	}
}

// credentialChecker error is fatal (refuse to risk resetting a rotated password).
func TestRunWithDeps_CredentialCheckErrorIsFatal(t *testing.T) {
	origChk := credentialChecker
	t.Cleanup(func() { credentialChecker = origChk })
	credentialChecker = func(context.Context, *rest.Config, string, string) (bool, error) {
		return false, errors.New("apiserver blip")
	}
	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	code := runWithDeps(context.Background(), discardLogger(), &bytes.Buffer{},
		"acme", "owner@acme.example", "", true, "gibson-first-admin", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return &fakeIdpClient{createUserID: "u1"}, nil },
		func(_ context.Context) (fgaClient, error) { return &fakeFgaClient{}, nil },
	)
	if code != 1 {
		t.Fatalf("credential-check error must be fatal, exit=%d", code)
	}
}

// A failed org-member grant is logged as a warning but the run still succeeds.
func TestRunWithDeps_MembershipWarningLoggedNonFatal(t *testing.T) {
	origChk := credentialChecker
	t.Cleanup(func() { credentialChecker = origChk })
	credentialChecker = func(context.Context, *rest.Config, string, string) (bool, error) { return false, nil }
	origW := credentialWriter
	t.Cleanup(func() { credentialWriter = origW })
	credentialWriter = func(context.Context, *rest.Config, string, string, string, string) error { return nil }
	origPA := foundingMemberPreAcceptor
	t.Cleanup(func() { foundingMemberPreAcceptor = origPA })
	foundingMemberPreAcceptor = func(context.Context, *rest.Config, string, string, string) (preAcceptOutcome, error) {
		return preAcceptDone, nil
	}

	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	idpC := &fakeIdpClient{createUserID: "u1", addMemberErr: errors.New("gibson.owner undefined")}
	code := runWithDeps(context.Background(), discardLogger(), &bytes.Buffer{},
		"acme", "owner@acme.example", "", true, "gibson-first-admin", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return &fakeFgaClient{}, nil },
	)
	if code != 0 {
		t.Fatalf("a failed org-member grant must not fail the run, exit=%d", code)
	}
}

// --- spent-credential expiry -------------------------------------------------
//
// The Secret says "sign in, change it, then delete this Secret". Operators skip
// the delete, so the bootstrap does it — but ONLY when the recorded password is
// provably no longer the account's password. Every test below guards one half of
// that: the deletes that must happen, and the deletes that must never happen.

// firstAdminSecret builds a Secret shaped exactly like writeCredentialSecret's,
// created at the given time.
func firstAdminSecret(created time.Time) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "gibson-first-admin",
			Namespace:         "gibson",
			UID:               "uid-1",
			ResourceVersion:   "7",
			CreationTimestamp: metav1.NewTime(created),
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "bootstrap-tenant-owner",
			},
		},
		StringData: map[string]string{"password": "initial"},
	}
}

func secretGone(t *testing.T, cs kubernetes.Interface) bool {
	t.Helper()
	_, err := cs.CoreV1().Secrets("gibson").Get(context.Background(), "gibson-first-admin", metav1.GetOptions{})
	return apierrors.IsNotFound(err)
}

// The whole point: a password changed after the Secret was written means the
// Secret holds a value Zitadel no longer accepts, so it must not survive.
func TestExpireSpentCredential_DeletesAfterPasswordChange(t *testing.T) {
	created := time.Date(2026, 8, 26, 13, 27, 33, 0, time.UTC)
	cs := k8sfake.NewSimpleClientset(firstAdminSecret(created))

	deleted, err := expireSpentCredential(context.Background(), cs, "gibson", "gibson-first-admin",
		created.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !deleted {
		t.Fatal("a password changed 2h after the Secret was written makes it spent; it must be deleted")
	}
	if !secretGone(t, cs) {
		t.Fatal("reported deleted but the Secret is still there")
	}
}

// A zero timestamp means Zitadel holds no password-change record: the password
// is still the one set at user creation, so the Secret is LIVE. Deleting it
// would destroy the only copy of a working credential.
func TestExpireSpentCredential_KeepsWhenNeverChanged(t *testing.T) {
	created := time.Date(2026, 8, 26, 13, 27, 33, 0, time.UTC)
	cs := k8sfake.NewSimpleClientset(firstAdminSecret(created))

	deleted, err := expireSpentCredential(context.Background(), cs, "gibson", "gibson-first-admin", time.Time{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted || secretGone(t, cs) {
		t.Fatal("no recorded password change means the credential is live; it must be kept")
	}
}

// The two timestamps come from different clocks. A change stamped a few seconds
// after the Secret is skew, not a rotation, and must not cost the operator their
// only copy of the password.
func TestExpireSpentCredential_KeepsWithinSkewGuard(t *testing.T) {
	created := time.Date(2026, 8, 26, 13, 27, 33, 0, time.UTC)
	cs := k8sfake.NewSimpleClientset(firstAdminSecret(created))

	deleted, err := expireSpentCredential(context.Background(), cs, "gibson", "gibson-first-admin",
		created.Add(credentialSkewGuard-time.Second))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted || secretGone(t, cs) {
		t.Fatalf("a change within the %s skew guard is clock disagreement, not a rotation", credentialSkewGuard)
	}
}

// A password set BEFORE the Secret was written is what the Secret recorded. That
// is the ordinary post-install state and must not read as spent.
func TestExpireSpentCredential_KeepsWhenChangeIsOlderThanSecret(t *testing.T) {
	created := time.Date(2026, 8, 26, 13, 27, 33, 0, time.UTC)
	cs := k8sfake.NewSimpleClientset(firstAdminSecret(created))

	deleted, err := expireSpentCredential(context.Background(), cs, "gibson", "gibson-first-admin",
		created.Add(-time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted || secretGone(t, cs) {
		t.Fatal("a password set before the Secret is the one the Secret holds; it must be kept")
	}
}

// A Secret this binary did not write may hold anything — including a password an
// operator rotated to by hand. Never delete what we did not create.
func TestExpireSpentCredential_KeepsUnmanagedSecret(t *testing.T) {
	created := time.Date(2026, 8, 26, 13, 27, 33, 0, time.UTC)
	sec := firstAdminSecret(created)
	sec.Labels = map[string]string{"app.kubernetes.io/managed-by": "an-operator"}
	cs := k8sfake.NewSimpleClientset(sec)

	deleted, err := expireSpentCredential(context.Background(), cs, "gibson", "gibson-first-admin",
		created.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted || secretGone(t, cs) {
		t.Fatal("a Secret this binary did not write must never be deleted")
	}
}

// Nothing to expire is not an error: the operator already deleted it, exactly as
// the annotation asked.
func TestExpireSpentCredential_AbsentSecretIsNotAnError(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	deleted, err := expireSpentCredential(context.Background(), cs, "gibson", "gibson-first-admin", time.Now())
	if err != nil {
		t.Fatalf("an absent Secret is the desired end state, not an error: %v", err)
	}
	if deleted {
		t.Fatal("reported a delete with no Secret present")
	}
}

// --- spent-credential expiry: error branches ---------------------------------

// A get that fails for a reason OTHER than NotFound must be surfaced. Reporting
// "nothing to expire" on an API blip would be a silent no-op that looks like
// success, and the stale Secret would survive with nobody told.
func TestExpireSpentCredential_GetErrorIsSurfaced(t *testing.T) {
	cs := k8sfake.NewSimpleClientset()
	cs.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver exploded")
	})
	if _, err := expireSpentCredential(context.Background(), cs, "gibson", "gibson-first-admin", time.Now()); err == nil {
		t.Fatal("want the get error surfaced, not swallowed as nothing-to-do")
	}
}

// The delete carries UID and resourceVersion preconditions. A Conflict means
// something rewrote the Secret between the read and the delete, so this
// function's view of the content is stale — it must NOT report a delete, and
// must not treat the disagreement as an error either.
func TestExpireSpentCredential_DeleteConflictIsNotAnError(t *testing.T) {
	created := time.Date(2026, 8, 26, 13, 27, 33, 0, time.UTC)
	cs := k8sfake.NewSimpleClientset(firstAdminSecret(created))
	cs.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(
			schema.GroupResource{Resource: "secrets"}, "gibson-first-admin", errors.New("resourceVersion moved"))
	})
	deleted, err := expireSpentCredential(context.Background(), cs, "gibson", "gibson-first-admin",
		created.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("a precondition conflict is someone else winning the race, not an error: %v", err)
	}
	if deleted {
		t.Fatal("reported a delete that the apiserver rejected")
	}
}

// Any other delete failure is real and must be reported, so the operator learns
// the Secret still holds a password Zitadel no longer accepts.
func TestExpireSpentCredential_DeleteErrorIsSurfaced(t *testing.T) {
	created := time.Date(2026, 8, 26, 13, 27, 33, 0, time.UTC)
	cs := k8sfake.NewSimpleClientset(firstAdminSecret(created))
	cs.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver exploded")
	})
	if _, err := expireSpentCredential(context.Background(), cs, "gibson", "gibson-first-admin",
		created.Add(2*time.Hour)); err == nil {
		t.Fatal("want the delete error surfaced")
	}
}

// expireSpentCredentialViaConfig: a config the client cannot be built from
// errors early; a buildable config pointing at nothing fails at the Get.
func TestExpireSpentCredentialViaConfig(t *testing.T) {
	if _, err := expireSpentCredentialViaConfig(context.Background(),
		&rest.Config{Host: "https://127.0.0.1:1", Timeout: 500 * time.Millisecond},
		"gibson", "gibson-first-admin", time.Now()); err == nil {
		t.Fatal("expected an error against an unreachable apiserver")
	}
	if _, err := expireSpentCredentialViaConfig(context.Background(),
		&rest.Config{Host: "://not a url"}, "gibson", "gibson-first-admin", time.Now()); err == nil {
		t.Fatal("expected a client-construction error")
	}
}

// --- spent-credential expiry: the run() wiring -------------------------------
//
// The three tests below pin WHEN the expiry runs and that it can never fail the
// install. Expiring a credential is hygiene: an owner who can sign in with a
// password they set themselves is a working install, whatever the Secret says.

// reRunDeps returns the dependency set for a re-run (credential Secret already
// present), which is the only path that expires anything.
func reRunDeps(t *testing.T) (tenants *fakeTenantGetter, restore func()) {
	t.Helper()
	origChk, origPA := credentialChecker, foundingMemberPreAcceptor
	credentialChecker = func(context.Context, *rest.Config, string, string) (bool, error) { return true, nil }
	foundingMemberPreAcceptor = func(context.Context, *rest.Config, string, string, string) (preAcceptOutcome, error) {
		return preAcceptDone, nil
	}
	return &fakeTenantGetter{obj: makeTenant("acme", "org-1")}, func() {
		credentialChecker, foundingMemberPreAcceptor = origChk, origPA
	}
}

func runReRun(t *testing.T, tenants *fakeTenantGetter, idpC idpClient) int {
	t.Helper()
	return runWithDeps(context.Background(), discardLogger(), &bytes.Buffer{},
		"acme", "owner@acme.example", "", true, "gibson-first-admin", "gibson",
		happyKubeLoader,
		func(_ *rest.Config) (TenantGetter, error) { return tenants, nil },
		func(_ context.Context) (idpClient, error) { return idpC, nil },
		func(_ context.Context) (fgaClient, error) { return &fakeFgaClient{}, nil },
	)
}

// The happy path: on a re-run the owner's password-change time is read and
// handed to the expirer, scoped to the configured Secret.
func TestRunWithDeps_ExpiresSpentCredentialOnReRun(t *testing.T) {
	changed := time.Date(2026, 8, 26, 15, 27, 54, 0, time.UTC)
	idpC := &fakeIdpClient{findUserID: "u1", pwChangedAt: changed}
	tenants, restore := reRunDeps(t)
	t.Cleanup(restore)

	origExp := credentialExpirer
	t.Cleanup(func() { credentialExpirer = origExp })
	var gotNS, gotName string
	var gotAt time.Time
	calls := 0
	credentialExpirer = func(_ context.Context, _ *rest.Config, ns, name string, at time.Time) (bool, error) {
		calls++
		gotNS, gotName, gotAt = ns, name, at
		return true, nil
	}

	if code := runReRun(t, tenants, idpC); code != 0 {
		t.Fatalf("re-run must succeed, exit=%d", code)
	}
	if calls != 1 {
		t.Fatalf("expirer called %d times, want exactly 1", calls)
	}
	if gotNS != "gibson" || gotName != "gibson-first-admin" {
		t.Errorf("expirer scoped to %s/%s, want gibson/gibson-first-admin", gotNS, gotName)
	}
	if !gotAt.Equal(changed) {
		t.Errorf("expirer got password-change time %v, want %v", gotAt, changed)
	}
	if len(idpC.pwChangedCalls) != 1 || idpC.pwChangedCalls[0] != "u1" {
		t.Errorf("password-change read = %v, want one read for u1", idpC.pwChangedCalls)
	}
}

// Zitadel unreachable: without a change time there is no evidence the credential
// is spent, so the expirer must NOT be called and the run must still succeed.
// Deleting on a failed read would destroy a live credential over a network blip.
func TestRunWithDeps_PasswordChangeReadErrorLeavesSecretAlone(t *testing.T) {
	idpC := &fakeIdpClient{findUserID: "u1", pwChangedErr: errors.New("zitadel unreachable")}
	tenants, restore := reRunDeps(t)
	t.Cleanup(restore)

	origExp := credentialExpirer
	t.Cleanup(func() { credentialExpirer = origExp })
	calls := 0
	credentialExpirer = func(context.Context, *rest.Config, string, string, time.Time) (bool, error) {
		calls++
		return false, nil
	}

	if code := runReRun(t, tenants, idpC); code != 0 {
		t.Fatalf("a failed password-change read must not fail the run, exit=%d", code)
	}
	if calls != 0 {
		t.Fatal("expirer must not run without evidence the credential is spent")
	}
}

// A delete that fails is logged and survived. The owner can sign in; a Secret
// left behind is untidy, not broken.
func TestRunWithDeps_ExpiryErrorIsNonFatal(t *testing.T) {
	idpC := &fakeIdpClient{findUserID: "u1", pwChangedAt: time.Now()}
	tenants, restore := reRunDeps(t)
	t.Cleanup(restore)

	origExp := credentialExpirer
	t.Cleanup(func() { credentialExpirer = origExp })
	credentialExpirer = func(context.Context, *rest.Config, string, string, time.Time) (bool, error) {
		return false, errors.New("forbidden")
	}

	if code := runReRun(t, tenants, idpC); code != 0 {
		t.Fatalf("a failed expiry must not fail the run, exit=%d", code)
	}
}
