// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// machineAdminsMux is a fake Zitadel serving the project lookup, the member
// search seeded with members, and the member writes. fail maps a call name
// ("projects", "project", "search", "delete", "put") to the HTTP status that
// call returns instead of succeeding. A POST /admin/v1/members answers 409,
// as Zitadel does for an existing member, so AddIAMMember goes on to PUT the
// new role set, which is recorded in puts.
func machineAdminsMux(t *testing.T, members []iamMemberFixture, fail map[string]int) (srv *httptest.Server, removed *[]string, puts map[string][]string) {
	t.Helper()
	var rm []string
	puts = map[string][]string{}
	failed := func(w http.ResponseWriter, call string) bool {
		status, ok := fail[call]
		if !ok {
			return false
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"code":13,"message":"boom"}`))
		return true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, _ *http.Request) {
		if failed(w, "projects") {
			return
		}
		_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-1","name":"gibson"}]}`))
	})
	mux.HandleFunc("/management/v1/projects/PROJ-1", func(w http.ResponseWriter, _ *http.Request) {
		if failed(w, "project") {
			return
		}
		_, _ = w.Write([]byte(`{"project":{"details":{"resourceOwner":"ORG-1"}}}`))
	})
	mux.HandleFunc("/admin/v1/members/_search", func(w http.ResponseWriter, _ *http.Request) {
		if failed(w, "search") {
			return
		}
		_, _ = w.Write(membersSearchBody(members))
	})
	mux.HandleFunc("/admin/v1/members", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":6,"message":"member already exists"}`))
	})
	mux.HandleFunc("/admin/v1/members/", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Path[len("/admin/v1/members/"):]
		switch r.Method {
		case http.MethodDelete:
			if failed(w, "delete") {
				return
			}
			rm = append(rm, userID)
			_, _ = w.Write([]byte(`{}`))
		case http.MethodPut:
			if failed(w, "put") {
				return
			}
			var body struct {
				Roles []string `json:"roles"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			puts[userID] = body.Roles
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &rm, puts
}

// machineAdminsCR declares two MACHINE_USER children (the daemon and the
// tenant-operator) and one WEB client, the shape the chart renders.
func machineAdminsCR(zitadelURL string) *gibsonv1alpha1.PlatformBootstrap {
	pb := basePlatformOwnerCR(zitadelURL)
	pb.Spec.OIDCClients = []gibsonv1alpha1.OIDCClientReference{
		{Name: "gibson-daemon", ApplicationType: gibsonv1alpha1.OIDCAppTypeMachineUser},
		{Name: "gibson-tenant-operator", ApplicationType: gibsonv1alpha1.OIDCAppTypeMachineUser},
		{Name: "gibson-dashboard", ApplicationType: gibsonv1alpha1.OIDCAppTypeWeb},
	}
	return pb
}

func machineAdminsObjects() []client.Object {
	return []client.Object{
		adminPATSecret(),
		iamAdminSecret("UID-IAMADMIN"),
		machineUserChild("gibson-daemon", "UID-DAEMON"),
		machineUserChild("gibson-tenant-operator", "UID-TENANTOP"),
	}
}

// stagingMembers is the member list staging carried on 2026-09-27 after an
// upgrade from an older chart: gibson-signup-bot is a machine user no
// OIDCClient declares any more, and it still held two instance roles.
func stagingMembers() []iamMemberFixture {
	return []iamMemberFixture{
		{UserID: "UID-IAMADMIN", Roles: []string{"IAM_OWNER"}, PreferredLoginName: "iam-admin", UserType: "TYPE_MACHINE", UserResourceOwner: "ORG-1"},
		{UserID: "UID-LOGIN", Roles: []string{"IAM_LOGIN_CLIENT"}, PreferredLoginName: "login-client", UserType: "TYPE_MACHINE", UserResourceOwner: "ORG-1"},
		{UserID: "UID-SIGNUPBOT", Roles: []string{"IAM_USER_MANAGER", "IAM_LOGIN_CLIENT"}, PreferredLoginName: "gibson-signup-bot", UserType: "TYPE_MACHINE", UserResourceOwner: "ORG-1"},
		{UserID: "UID-OWNER", Roles: []string{"IAM_OWNER"}, PreferredLoginName: "owner@example.com", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
		{UserID: "UID-DAEMON", Roles: []string{"IAM_ORG_MANAGER"}, PreferredLoginName: "gibson-daemon", UserType: "TYPE_MACHINE", UserResourceOwner: "ORG-1"},
		{UserID: "UID-TENANTOP", Roles: []string{"IAM_ORG_MANAGER"}, PreferredLoginName: "gibson-tenant-operator", UserType: "TYPE_MACHINE", UserResourceOwner: "ORG-1"},
	}
}

func wantMachineAdminsCond(t *testing.T, pb *gibsonv1alpha1.PlatformBootstrap, status metav1.ConditionStatus, reason string) {
	t.Helper()
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionMachineAdminsScoped)
	if cond == nil || cond.Status != status || cond.Reason != reason {
		t.Fatalf("condition = %+v, want %s/%s", cond, status, reason)
	}
}

// TestReconcileMachineAdminsScoped_RemovesUndeclaredMachineAdmin pins the
// upgrade case: the undeclared machine user loses its membership, and the
// declared accounts, the login client and the human are untouched.
func TestReconcileMachineAdminsScoped_RemovesUndeclaredMachineAdmin(t *testing.T) {
	srv, removed, puts := machineAdminsMux(t, stagingMembers(), nil)
	r := newOwnerTestReconciler(t, srv.URL, "http://unused.invalid", machineAdminsObjects()...)
	pb := machineAdminsCR(srv.URL)

	res, err := r.reconcileMachineAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileMachineAdminsScoped: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	if !slices.Equal(*removed, []string{"UID-SIGNUPBOT"}) {
		t.Fatalf("RemoveIAMMember calls = %v, want exactly [UID-SIGNUPBOT]", *removed)
	}
	if len(puts) != 0 {
		t.Fatalf("role writes = %v, want none", puts)
	}
	wantMachineAdminsCond(t, pb, metav1.ConditionTrue, "Scoped")
}

// TestReconcileMachineAdminsScoped_ResetsWidenedLoginClient pins that the
// login client keeps its membership but never more than IAM_LOGIN_CLIENT.
func TestReconcileMachineAdminsScoped_ResetsWidenedLoginClient(t *testing.T) {
	members := stagingMembers()
	members[1].Roles = []string{"IAM_LOGIN_CLIENT", "IAM_OWNER"}
	srv, removed, puts := machineAdminsMux(t, members, nil)
	r := newOwnerTestReconciler(t, srv.URL, "http://unused.invalid", machineAdminsObjects()...)
	pb := machineAdminsCR(srv.URL)

	if _, err := r.reconcileMachineAdminsScoped(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileMachineAdminsScoped: %v", err)
	}
	if slices.Contains(*removed, "UID-LOGIN") {
		t.Fatal("the login client lost its membership")
	}
	if got := puts["UID-LOGIN"]; !slices.Equal(got, []string{"IAM_LOGIN_CLIENT"}) {
		t.Fatalf("login client roles written = %v, want [IAM_LOGIN_CLIENT]", got)
	}
	wantMachineAdminsCond(t, pb, metav1.ConditionTrue, "Scoped")
}

// TestReconcileMachineAdminsScoped_LoginClientNameInOtherOrg_Removed pins
// that the fixed username alone is not enough: a machine user named
// login-client in a tenant org is not the login client.
func TestReconcileMachineAdminsScoped_LoginClientNameInOtherOrg_Removed(t *testing.T) {
	members := append(stagingMembers(), iamMemberFixture{
		UserID: "UID-FAKELOGIN", Roles: []string{"IAM_LOGIN_CLIENT"}, PreferredLoginName: "login-client", UserType: "TYPE_MACHINE", UserResourceOwner: "ORG-TENANT",
	})
	srv, removed, _ := machineAdminsMux(t, members, nil)
	r := newOwnerTestReconciler(t, srv.URL, "http://unused.invalid", machineAdminsObjects()...)
	pb := machineAdminsCR(srv.URL)

	if _, err := r.reconcileMachineAdminsScoped(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileMachineAdminsScoped: %v", err)
	}
	if !slices.Equal(*removed, []string{"UID-SIGNUPBOT", "UID-FAKELOGIN"}) {
		t.Fatalf("RemoveIAMMember calls = %v, want [UID-SIGNUPBOT UID-FAKELOGIN]", *removed)
	}
}

// TestReconcileMachineAdminsScoped_WaitsForMachineUsers pins the safety
// rule: while a declared child is not Ready, nothing is removed, because
// that child may already be a member this step cannot yet name.
func TestReconcileMachineAdminsScoped_WaitsForMachineUsers(t *testing.T) {
	srv, removed, _ := machineAdminsMux(t, stagingMembers(), nil)
	r := newOwnerTestReconciler(t, srv.URL, "http://unused.invalid",
		adminPATSecret(), iamAdminSecret("UID-IAMADMIN"), machineUserChild("gibson-daemon", "UID-DAEMON"))
	pb := machineAdminsCR(srv.URL)

	res, err := r.reconcileMachineAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileMachineAdminsScoped: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue while a declared machine user is pending")
	}
	if len(*removed) != 0 {
		t.Fatalf("RemoveIAMMember calls = %v, want none", *removed)
	}
	wantMachineAdminsCond(t, pb, metav1.ConditionFalse, "WaitingForMachineUsers")
}

func TestReconcileMachineAdminsScoped_WaitsForIAMAdminSecret(t *testing.T) {
	r := newOwnerTestReconciler(t, "http://unused.invalid", "http://unused.invalid", adminPATSecret())
	pb := machineAdminsCR("http://unused.invalid")

	res, err := r.reconcileMachineAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileMachineAdminsScoped: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue while the iam-admin Secret is missing")
	}
	wantMachineAdminsCond(t, pb, metav1.ConditionFalse, "WaitingForIAMAdminSecret")
}

// TestReconcileMachineAdminsScoped_ZitadelErrors pins every Zitadel failure
// path: a failed project lookup waits, a transient error requeues, and a
// permanent error stops without a requeue.
func TestReconcileMachineAdminsScoped_ZitadelErrors(t *testing.T) {
	widened := stagingMembers()
	widened[1].Roles = []string{"IAM_OWNER"}
	cases := []struct {
		name        string
		members     []iamMemberFixture
		fail        map[string]int
		wantStatus  metav1.ConditionStatus
		wantReason  string
		wantRequeue bool
	}{
		{"project search", stagingMembers(), map[string]int{"projects": http.StatusServiceUnavailable}, metav1.ConditionUnknown, "WaitingForProject", true},
		{"project org", stagingMembers(), map[string]int{"project": http.StatusServiceUnavailable}, metav1.ConditionUnknown, "WaitingForProject", true},
		{"member search transient", stagingMembers(), map[string]int{"search": http.StatusServiceUnavailable}, metav1.ConditionUnknown, "ZitadelTransientError", true},
		{"member search permanent", stagingMembers(), map[string]int{"search": http.StatusForbidden}, metav1.ConditionFalse, "ZitadelPermanentError", false},
		{"remove transient", stagingMembers(), map[string]int{"delete": http.StatusServiceUnavailable}, metav1.ConditionUnknown, "ZitadelTransientError", true},
		{"remove permanent", stagingMembers(), map[string]int{"delete": http.StatusForbidden}, metav1.ConditionFalse, "ZitadelPermanentError", false},
		{"login client reset", widened, map[string]int{"put": http.StatusForbidden}, metav1.ConditionFalse, "ZitadelPermanentError", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := machineAdminsMux(t, tc.members, tc.fail)
			r := newOwnerTestReconciler(t, srv.URL, "http://unused.invalid", machineAdminsObjects()...)
			pb := machineAdminsCR(srv.URL)

			res, err := r.reconcileMachineAdminsScoped(context.Background(), pb, logr.Discard())
			if err != nil {
				t.Fatalf("reconcileMachineAdminsScoped: %v", err)
			}
			if (res.RequeueAfter != 0) != tc.wantRequeue {
				t.Fatalf("result = %+v, want requeue=%v", res, tc.wantRequeue)
			}
			wantMachineAdminsCond(t, pb, tc.wantStatus, tc.wantReason)
		})
	}
}

func TestReconcileMachineAdminsScoped_WaitsForAdminToken(t *testing.T) {
	r := newOwnerTestReconciler(t, "http://unused.invalid", "http://unused.invalid",
		iamAdminSecret("UID-IAMADMIN"),
		machineUserChild("gibson-daemon", "UID-DAEMON"),
		machineUserChild("gibson-tenant-operator", "UID-TENANTOP"))
	pb := machineAdminsCR("http://unused.invalid")

	res, err := r.reconcileMachineAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileMachineAdminsScoped: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue while the admin token Secret is missing")
	}
	wantMachineAdminsCond(t, pb, metav1.ConditionFalse, "WaitingForAdminToken")
}

// TestReconcileMachineAdminsScoped_APIErrorsReturned pins that a Kubernetes
// API error reading the service accounts or the admin token is returned, so
// controller-runtime retries with backoff.
func TestReconcileMachineAdminsScoped_APIErrorsReturned(t *testing.T) {
	for _, name := range []string{iamAdminSecretName, "iam-admin-pat"} {
		t.Run(name, func(t *testing.T) {
			r := newOwnerTestReconciler(t, "http://unused.invalid", "http://unused.invalid", machineAdminsObjects()...)
			r.Client = failGetNamed(r.Client.(client.WithWatch), name)
			pb := machineAdminsCR("http://unused.invalid")

			if _, err := r.reconcileMachineAdminsScoped(context.Background(), pb, logr.Discard()); err == nil {
				t.Fatal("expected the API error to be returned")
			}
		})
	}
}

func TestIsLoginClient(t *testing.T) {
	m := zitadel.IAMMember{UserID: "UID-LOGIN", PreferredLoginName: "login-client", UserType: zitadel.ZitadelUserTypeMachine, UserResourceOwner: "ORG-1"}
	if !isLoginClient(m, "ORG-1") {
		t.Fatal("the setup-created login client was not recognized")
	}
	if isLoginClient(m, "ORG-OTHER") {
		t.Fatal("a login-client in another org was recognized")
	}
	m.UserType = zitadel.ZitadelUserTypeHuman
	if isLoginClient(m, "ORG-1") {
		t.Fatal("a human named login-client was recognized")
	}
	m.UserType = zitadel.ZitadelUserTypeMachine
	m.PreferredLoginName = "login-client-2"
	if isLoginClient(m, "ORG-1") {
		t.Fatal("a machine user with another username was recognized")
	}
}
