// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestMain neutralises the real pre-acceptor for the whole package: every
// pre-existing runWithDeps test would otherwise dial a Kubernetes API server
// that does not exist. Tests that assert pre-accept behaviour swap the var
// themselves (with t.Cleanup restoring this stub, not the real client).
func TestMain(m *testing.M) {
	foundingMemberPreAcceptor = func(context.Context, *rest.Config, string, string, string) (preAcceptOutcome, error) {
		return preAcceptDone, nil
	}
	os.Exit(m.Run())
}

func memberObj(ns, name, email, role, acceptedBy string) *unstructured.Unstructured {
	spec := map[string]interface{}{
		"email": email,
		"role":  role,
	}
	if acceptedBy != "" {
		spec["acceptedByUserId"] = acceptedBy
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "gibson.zeroroot.ai/v1alpha1",
		"kind":       "TenantMember",
		"metadata":   map[string]interface{}{"name": name, "namespace": ns},
		"spec":       spec,
	}}
}

func newFakeDyn(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{tenantMembersGVR: "TenantMemberList"}, objs...)
}

// The vanilla-install defect this exists for: the founding owner sat Invited,
// so the member reconciler never seeded the active_session tuples and every
// tenant-scoped RPC failed closed at the session gate while login worked.
func TestPreAcceptFoundingMember_StampsTheOwner(t *testing.T) {
	dyn := newFakeDyn(memberObj("tenant-primary", "admin-owner", "admin@selfhosted.example.com", "owner", ""))

	outcome, err := preAcceptFoundingMember(context.Background(), dyn, "primary", "admin@selfhosted.example.com", "u-42")
	if err != nil {
		t.Fatalf("preAcceptFoundingMember: %v", err)
	}
	if outcome != preAcceptDone {
		t.Fatalf("outcome = %q, want %q", outcome, preAcceptDone)
	}

	got, err := dyn.Resource(tenantMembersGVR).Namespace("tenant-primary").Get(context.Background(), "admin-owner", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	accepted, _, _ := unstructured.NestedString(got.Object, "spec", "acceptedByUserId")
	if accepted != "u-42" {
		t.Fatalf("acceptedByUserID = %q, want u-42", accepted)
	}
}

// Re-running the bootstrap must not disturb an accepted membership.
func TestPreAcceptFoundingMember_AlreadyAcceptedIsANoOp(t *testing.T) {
	dyn := newFakeDyn(memberObj("tenant-primary", "admin-owner", "admin@selfhosted.example.com", "owner", "u-1"))

	outcome, err := preAcceptFoundingMember(context.Background(), dyn, "primary", "admin@selfhosted.example.com", "u-42")
	if err != nil {
		t.Fatalf("preAcceptFoundingMember: %v", err)
	}
	if outcome != preAcceptAlreadySet {
		t.Fatalf("outcome = %q, want %q", outcome, preAcceptAlreadySet)
	}
	got, _ := dyn.Resource(tenantMembersGVR).Namespace("tenant-primary").Get(context.Background(), "admin-owner", metav1.GetOptions{})
	accepted, _, _ := unstructured.NestedString(got.Object, "spec", "acceptedByUserId")
	if accepted != "u-1" {
		t.Fatalf("acceptedByUserID = %q; a re-run must not overwrite the original acceptor", accepted)
	}
}

// An install with no founding-member CR has nothing to pre-accept: report,
// never fail — the FGA owner tuple already grants ownership.
// The self-hosted first-run race: the pre-accept runs BEFORE the reconcile
// creates the founding member. It must not give up (which left the owner Invited
// forever) — it creates the member already-accepted with the canonical name.
func TestPreAcceptFoundingMember_NoMemberCreatesAccepted(t *testing.T) {
	dyn := newFakeDyn()

	outcome, err := preAcceptFoundingMember(context.Background(), dyn, "primary", "admin@selfhosted.example.com", "u-42")
	if err != nil {
		t.Fatalf("preAcceptFoundingMember: %v", err)
	}
	if outcome != preAcceptCreated {
		t.Fatalf("outcome = %q, want %q", outcome, preAcceptCreated)
	}
	// The member CR now exists, accepted, with the canonical name + spec.
	name := "admin-selfhosted-example-com-owner"
	got, err := dyn.Resource(tenantMembersGVR).Namespace("tenant-primary").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get created member %q: %v", name, err)
	}
	if a, _, _ := unstructured.NestedString(got.Object, "spec", "acceptedByUserId"); a != "u-42" {
		t.Errorf("acceptedByUserId = %q, want u-42", a)
	}
	if r, _, _ := unstructured.NestedString(got.Object, "spec", "role"); r != "owner" {
		t.Errorf("role = %q, want owner", r)
	}
	if e, _, _ := unstructured.NestedString(got.Object, "spec", "email"); e != "admin@selfhosted.example.com" {
		t.Errorf("email = %q", e)
	}
	if tr, _, _ := unstructured.NestedString(got.Object, "spec", "tenantRef", "name"); tr != "primary" {
		t.Errorf("tenantRef.name = %q, want primary", tr)
	}
}

// Only the owner-role member matching the email is stamped; an unrelated
// invitee stays untouched.
func TestPreAcceptFoundingMember_MatchesByEmailAndRole(t *testing.T) {
	dyn := newFakeDyn(
		memberObj("tenant-primary", "teammate", "teammate@selfhosted.example.com", "member", ""),
		memberObj("tenant-primary", "admin-owner", "Admin@Selfhosted.Example.Com", "owner", ""),
	)

	outcome, err := preAcceptFoundingMember(context.Background(), dyn, "primary", "admin@selfhosted.example.com", "u-42")
	if err != nil || outcome != preAcceptDone {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	teammate, _ := dyn.Resource(tenantMembersGVR).Namespace("tenant-primary").Get(context.Background(), "teammate", metav1.GetOptions{})
	if accepted, _, _ := unstructured.NestedString(teammate.Object, "spec", "acceptedByUserId"); accepted != "" {
		t.Fatalf("the invitee must stay untouched, got acceptedByUserID=%q", accepted)
	}
}

// A patch failure is a real error: an owner who can log in and do nothing is a
// broken install wearing a working login.
func TestPreAcceptFoundingMember_PatchFailureSurfaces(t *testing.T) {
	dyn := newFakeDyn(memberObj("tenant-primary", "admin-owner", "admin@selfhosted.example.com", "owner", ""))
	dyn.PrependReactor("patch", "tenantmembers", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("webhook says no")
	})

	if _, err := preAcceptFoundingMember(context.Background(), dyn, "primary", "admin@selfhosted.example.com", "u-42"); err == nil {
		t.Fatal("a patch failure must surface")
	}
}

// A pre-accept failure fails the run: an owner who can log in and do nothing
// is a broken install wearing a working login.
func TestRunWithDeps_PreAcceptFailureIsFatal(t *testing.T) {
	orig := foundingMemberPreAcceptor
	t.Cleanup(func() { foundingMemberPreAcceptor = orig })
	foundingMemberPreAcceptor = func(context.Context, *rest.Config, string, string, string) (preAcceptOutcome, error) {
		return "", errors.New("api server unreachable")
	}

	tenants := &fakeTenantGetter{obj: makeTenant("acme", "org-1")}
	code := runWithDeps(context.Background(), discardLogger(), &bytes.Buffer{},
		"acme", "owner@acme.example", "", false, "", "",
		happyKubeLoader,
		func(*rest.Config) (TenantGetter, error) { return tenants, nil },
		func(context.Context) (idpClient, error) { return &fakeIdpClient{createUserID: "u1"}, nil },
		func(context.Context) (fgaClient, error) { return &fakeFgaClient{}, nil },
	)
	if code != 1 {
		t.Fatalf("a pre-accept failure must be fatal, exit=%d", code)
	}
}

// A NotFound on the List — the per-tenant namespace or CRD absent — is the
// nothing-to-pre-accept case, not a failure.
func TestPreAcceptFoundingMember_ListNotFoundCreatesAccepted(t *testing.T) {
	dyn := newFakeDyn()
	dyn.PrependReactor("list", "tenantmembers", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Group: "gibson.zeroroot.ai", Resource: "tenantmembers"}, "")
	})

	outcome, err := preAcceptFoundingMember(context.Background(), dyn, "primary", "admin@selfhosted.example.com", "u-42")
	if err != nil || outcome != preAcceptCreated {
		t.Fatalf("outcome=%q err=%v, want %q with no error", outcome, err, preAcceptCreated)
	}
}

// The tight race: our find misses the member but the reconcile has just created
// it (AlreadyExists on create) — we accept the existing one instead of failing.
func TestPreAcceptFoundingMember_CreateRaceAcceptsExisting(t *testing.T) {
	dyn := newFakeDyn()
	// find (list) returns empty so we take the create path...
	dyn.PrependReactor("list", "tenantmembers", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &unstructured.UnstructuredList{}, nil
	})
	// ...but the create collides with a member the reconcile just wrote.
	dyn.PrependReactor("create", "tenantmembers", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Group: "gibson.zeroroot.ai", Resource: "tenantmembers"}, "admin-selfhosted-example-com-owner")
	})
	var patched bool
	dyn.PrependReactor("patch", "tenantmembers", func(k8stesting.Action) (bool, runtime.Object, error) {
		patched = true
		return true, memberObj("tenant-primary", "admin-selfhosted-example-com-owner", "admin@selfhosted.example.com", "owner", "u-42"), nil
	})

	outcome, err := preAcceptFoundingMember(context.Background(), dyn, "primary", "admin@selfhosted.example.com", "u-42")
	if err != nil || outcome != preAcceptDone {
		t.Fatalf("outcome=%q err=%v, want %q", outcome, err, preAcceptDone)
	}
	if !patched {
		t.Error("an AlreadyExists on create must fall back to accepting the existing member")
	}
}

// Any other List failure surfaces: an API blip must not read as "no member",
// or the run reports success against an install it never inspected.
func TestPreAcceptFoundingMember_ListFailureSurfaces(t *testing.T) {
	dyn := newFakeDyn()
	dyn.PrependReactor("list", "tenantmembers", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver hiccup")
	})

	if _, err := preAcceptFoundingMember(context.Background(), dyn, "primary", "admin@selfhosted.example.com", "u-42"); err == nil {
		t.Fatal("a non-NotFound list failure must surface")
	}
}

// The real-client wrapper: a well-formed rest.Config builds a client (no dial
// at construction) and the failure comes from the API call — proving the
// wrapper wires config → client → delegate rather than short-circuiting.
func TestPreAcceptFoundingMemberViaConfig_BuildsAClientAndDelegates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := preAcceptFoundingMemberViaConfig(ctx, &rest.Config{Host: "http://127.0.0.1:1"},
		"primary", "admin@selfhosted.example.com", "u-42")
	if err == nil {
		t.Fatal("a config pointing at nothing must surface a list error")
	}
}

// The patch key must be the API server's serialized field name, not the Go
// field name. A wrong key is silently PRUNED by the CRD schema while the
// patch reports success — which is exactly how the first live run no-opped
// ("acceptedByUserID" with a capital D). Pin the constant to the real type's
// json tag so the two can never drift apart.
func TestAcceptedByField_MatchesTheCRDSerializedName(t *testing.T) {
	f, ok := reflect.TypeOf(gibsonv1alpha1.TenantMemberSpec{}).FieldByName("AcceptedByUserID")
	if !ok {
		t.Fatal("TenantMemberSpec no longer has AcceptedByUserID — update the pre-accept")
	}
	tag := strings.Split(f.Tag.Get("json"), ",")[0]
	if tag != acceptedByField {
		t.Fatalf("acceptedByField = %q but the CRD serializes %q — the patch would be pruned silently", acceptedByField, tag)
	}
}
