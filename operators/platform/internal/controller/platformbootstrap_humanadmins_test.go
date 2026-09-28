// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// iamMemberFixture mirrors one result row of a real
// POST /admin/v1/members/_search response (field names and shapes pinned
// against a staging capture, hosted#189): userType is
// "TYPE_HUMAN"/"TYPE_MACHINE", and userResourceOwner (the org the USER
// belongs to) is distinct from the per-row details.resourceOwner (the
// instance's default org, constant across every row).
type iamMemberFixture struct {
	UserID             string
	Roles              []string
	PreferredLoginName string
	Email              string
	DisplayName        string
	UserType           string
	UserResourceOwner  string
}

func membersSearchBody(members []iamMemberFixture) []byte {
	type resultRow struct {
		UserID             string   `json:"userId"`
		Roles              []string `json:"roles"`
		PreferredLoginName string   `json:"preferredLoginName"`
		Email              string   `json:"email,omitempty"`
		DisplayName        string   `json:"displayName"`
		UserType           string   `json:"userType"`
		UserResourceOwner  string   `json:"userResourceOwner"`
		Details            struct {
			ResourceOwner string `json:"resourceOwner"`
		} `json:"details"`
	}
	resp := struct {
		Details struct {
			TotalResult string `json:"totalResult"`
		} `json:"details"`
		Result []resultRow `json:"result"`
	}{}
	resp.Details.TotalResult = strconv.Itoa(len(members))
	for _, m := range members {
		row := resultRow{
			UserID:             m.UserID,
			Roles:              m.Roles,
			PreferredLoginName: m.PreferredLoginName,
			Email:              m.Email,
			DisplayName:        m.DisplayName,
			UserType:           m.UserType,
			UserResourceOwner:  m.UserResourceOwner,
		}
		row.Details.ResourceOwner = "INSTANCE-DEFAULT-ORG"
		resp.Result = append(resp.Result, row)
	}
	b, _ := json.Marshal(resp)
	return b
}

// humanAdminsMux builds a fake Zitadel handler serving GetProjectIDByName +
// GetOrgIDForProject (both reconcileHumanAdminsScoped resolves fresh, same
// as reconcilePlatformOwner) plus /admin/v1/members/_search seeded with
// members, and records every RemoveIAMMember / DeleteUser call.
func humanAdminsMux(t *testing.T, members []iamMemberFixture) (srv *httptest.Server, removedIAM, deletedUsers *[]string) {
	t.Helper()
	var removed, deleted []string
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-1","name":"gibson"}]}`))
	})
	mux.HandleFunc("/management/v1/projects/PROJ-1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"project":{"details":{"resourceOwner":"ORG-1"}}}`))
	})
	mux.HandleFunc("/admin/v1/members/_search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(membersSearchBody(members))
	})
	mux.HandleFunc("/admin/v1/members/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		userID := r.URL.Path[len("/admin/v1/members/"):]
		removed = append(removed, userID)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/zitadel.user.v2.UserService/DeleteUser", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID string `json:"userId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		deleted = append(deleted, req.UserID)
		_, _ = w.Write([]byte(`{}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &removed, &deleted
}

func humanAdminsCR(zitadelURL string) *gibsonv1alpha1.PlatformBootstrap {
	pb := basePlatformOwnerCR(zitadelURL)
	pb.Spec.PlatformOwner.Email = "owner@example.com"
	pb.Status.PlatformOwnerUserID = "UID-OWNER"
	return pb
}

func newHumanAdminsTestReconciler(t *testing.T, zitadelURL string) *PlatformBootstrapReconciler {
	t.Helper()
	r := newOwnerTestReconciler(t, zitadelURL, "http://unused.invalid", adminPATSecret())
	return r
}

// TestReconcileHumanAdminsScoped_NotConfigured_Skips pins the same
// fail-safe reconcilePlatformOwner uses: with no Platform owner declared,
// there is nobody to keep, so the step does nothing rather than revoke
// every human admin.
func TestReconcileHumanAdminsScoped_NotConfigured_Skips(t *testing.T) {
	r := newHumanAdminsTestReconciler(t, "http://unused.invalid")
	pb := basePlatformOwnerCR("http://unused.invalid")
	// spec.platformOwner.email left empty.

	res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileHumanAdminsScoped: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionHumanAdminsScoped)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "NotConfigured" {
		t.Fatalf("condition = %+v, want True/NotConfigured", cond)
	}
}

// TestReconcileHumanAdminsScoped_WaitingForPlatformOwner pins the defensive
// guard: a configured Platform owner whose userID has not yet been
// persisted must never be treated as "nobody to keep."
func TestReconcileHumanAdminsScoped_WaitingForPlatformOwner(t *testing.T) {
	r := newHumanAdminsTestReconciler(t, "http://unused.invalid")
	pb := basePlatformOwnerCR("http://unused.invalid")
	pb.Spec.PlatformOwner.Email = "owner@example.com"
	// Status.PlatformOwnerUserID left empty.

	res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileHumanAdminsScoped: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue while waiting for the Platform owner")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionHumanAdminsScoped)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "WaitingForPlatformOwner" {
		t.Fatalf("condition = %+v, want False/WaitingForPlatformOwner", cond)
	}
}

func TestReconcileHumanAdminsScoped_WaitingForAdminToken(t *testing.T) {
	// No adminPATSecret object: readSecretKey must find nothing.
	r := newOwnerTestReconciler(t, "http://unused.invalid", "http://unused.invalid")
	pb := humanAdminsCR("http://unused.invalid")

	res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileHumanAdminsScoped: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue while waiting for the admin token Secret")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionHumanAdminsScoped)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "WaitingForAdminToken" {
		t.Fatalf("condition = %+v, want False/WaitingForAdminToken", cond)
	}
}

// TestReconcileHumanAdminsScoped_CleanInstance_NoOp pins the steady state:
// only the Platform owner is a human IAM member, so nothing is removed.
func TestReconcileHumanAdminsScoped_CleanInstance_NoOp(t *testing.T) {
	srv, removedIAM, deletedUsers := humanAdminsMux(t, []iamMemberFixture{
		{UserID: "UID-OWNER", PreferredLoginName: "owner@example.com", DisplayName: "Platform Owner", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
		{UserID: "UID-IAMADMIN", PreferredLoginName: "iam-admin", DisplayName: "Automatically Initialized IAM Admin", UserType: "TYPE_MACHINE", UserResourceOwner: "ORG-1"},
	})
	r := newHumanAdminsTestReconciler(t, srv.URL)
	pb := humanAdminsCR(srv.URL)

	res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileHumanAdminsScoped: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	if len(*removedIAM) != 0 {
		t.Fatalf("RemoveIAMMember called for %v, want none", *removedIAM)
	}
	if len(*deletedUsers) != 0 {
		t.Fatalf("DeleteUser called for %v, want none", *deletedUsers)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionHumanAdminsScoped)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "Scoped" {
		t.Fatalf("condition = %+v, want True/Scoped", cond)
	}
}

// TestReconcileHumanAdminsScoped_RemovesDefaultAdmin pins the core finding:
// Zitadel's own default first-instance human admin (zitadel-admin@..., in
// the same org as the gibson project) is both de-membered AND deleted.
func TestReconcileHumanAdminsScoped_RemovesDefaultAdmin(t *testing.T) {
	srv, removedIAM, deletedUsers := humanAdminsMux(t, []iamMemberFixture{
		{UserID: "UID-OWNER", PreferredLoginName: "owner@example.com", DisplayName: "Platform Owner", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
		{UserID: "UID-DEFAULT", PreferredLoginName: "zitadel-admin@zitadel.app.example.test", Email: "zitadel-admin@zitadel.app.example.test", DisplayName: "ZITADEL Admin", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
		{UserID: "UID-IAMADMIN", PreferredLoginName: "iam-admin", DisplayName: "Automatically Initialized IAM Admin", UserType: "TYPE_MACHINE", UserResourceOwner: "ORG-1"},
	})
	r := newHumanAdminsTestReconciler(t, srv.URL)
	pb := humanAdminsCR(srv.URL)

	res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileHumanAdminsScoped: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	if len(*removedIAM) != 1 || (*removedIAM)[0] != "UID-DEFAULT" {
		t.Fatalf("RemoveIAMMember calls = %v, want exactly [UID-DEFAULT]", *removedIAM)
	}
	if len(*deletedUsers) != 1 || (*deletedUsers)[0] != "UID-DEFAULT" {
		t.Fatalf("DeleteUser calls = %v, want exactly [UID-DEFAULT]", *deletedUsers)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionHumanAdminsScoped)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "Scoped" {
		t.Fatalf("condition = %+v, want True/Scoped", cond)
	}
}

// TestReconcileHumanAdminsScoped_RemovesSecondHumanAdmin_ButKeepsAccount
// pins that a second human granted IAM_OWNER out of band (not Zitadel's
// default admin — e.g. a different org, or a login name that does not
// match the default prefix) has its IAM membership revoked but its
// Zitadel account left alone: only the identified default admin is
// deleted outright.
func TestReconcileHumanAdminsScoped_RemovesSecondHumanAdmin_ButKeepsAccount(t *testing.T) {
	srv, removedIAM, deletedUsers := humanAdminsMux(t, []iamMemberFixture{
		{UserID: "UID-OWNER", PreferredLoginName: "owner@example.com", DisplayName: "Platform Owner", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
		{UserID: "UID-ROGUE", PreferredLoginName: "someone-else@example.com", DisplayName: "Someone Else", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
	})
	r := newHumanAdminsTestReconciler(t, srv.URL)
	pb := humanAdminsCR(srv.URL)

	res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileHumanAdminsScoped: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	if len(*removedIAM) != 1 || (*removedIAM)[0] != "UID-ROGUE" {
		t.Fatalf("RemoveIAMMember calls = %v, want exactly [UID-ROGUE]", *removedIAM)
	}
	if len(*deletedUsers) != 0 {
		t.Fatalf("DeleteUser calls = %v, want none (not the identified default admin)", *deletedUsers)
	}
}

// TestReconcileHumanAdminsScoped_DifferentOrg_NotDeleted pins the org check
// in isDefaultFirstInstanceAdmin: a "zitadel-admin@..." human in a
// DIFFERENT org than the one that owns the gibson project is still
// de-membered (it is human, and not the Platform owner) but not deleted —
// it cannot be Zitadel's own first-instance default admin.
func TestReconcileHumanAdminsScoped_DifferentOrg_NotDeleted(t *testing.T) {
	srv, removedIAM, deletedUsers := humanAdminsMux(t, []iamMemberFixture{
		{UserID: "UID-OWNER", PreferredLoginName: "owner@example.com", DisplayName: "Platform Owner", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
		{UserID: "UID-OTHERORG", PreferredLoginName: "zitadel-admin@zitadel.other.test", DisplayName: "ZITADEL Admin", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-2"},
	})
	r := newHumanAdminsTestReconciler(t, srv.URL)
	pb := humanAdminsCR(srv.URL)

	if _, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileHumanAdminsScoped: %v", err)
	}
	if len(*removedIAM) != 1 || (*removedIAM)[0] != "UID-OTHERORG" {
		t.Fatalf("RemoveIAMMember calls = %v, want exactly [UID-OTHERORG]", *removedIAM)
	}
	if len(*deletedUsers) != 0 {
		t.Fatalf("DeleteUser calls = %v, want none (different org)", *deletedUsers)
	}
}

func TestReconcileHumanAdminsScoped_GetProjectIDByNameError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	r := newHumanAdminsTestReconciler(t, srv.URL)
	pb := humanAdminsCR(srv.URL)

	res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileHumanAdminsScoped: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue when GetProjectIDByName fails")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionHumanAdminsScoped)
	if cond == nil || cond.Reason != "WaitingForProject" {
		t.Fatalf("condition = %+v, want reason WaitingForProject", cond)
	}
}

func TestReconcileHumanAdminsScoped_GetOrgIDForProjectError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-1","name":"gibson"}]}`))
	})
	mux.HandleFunc("/management/v1/projects/PROJ-1", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	r := newHumanAdminsTestReconciler(t, srv.URL)
	pb := humanAdminsCR(srv.URL)

	res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileHumanAdminsScoped: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue when GetOrgIDForProject fails")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionHumanAdminsScoped)
	if cond == nil || cond.Reason != "WaitingForProject" {
		t.Fatalf("condition = %+v, want reason WaitingForProject", cond)
	}
}

// humanAdminsMuxWithFailure builds the standard project/org-resolution mux
// (as humanAdminsMux does) but overrides one path to fail, so a single step
// downstream of project/org resolution can be tested in isolation.
func humanAdminsMuxWithFailure(t *testing.T, failPath string, status int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-1","name":"gibson"}]}`))
	})
	mux.HandleFunc("/management/v1/projects/PROJ-1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"project":{"details":{"resourceOwner":"ORG-1"}}}`))
	})
	mux.HandleFunc(failPath, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if status == http.StatusForbidden {
			_, _ = w.Write([]byte(`{"code":"permission_denied","message":"denied"}`))
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestReconcileHumanAdminsScoped_SearchIAMMembersErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		wantReason  string
		wantRequeue bool
	}{
		{"permanent", http.StatusForbidden, "ZitadelPermanentError", false},
		{"transient", http.StatusInternalServerError, "ZitadelTransientError", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := humanAdminsMuxWithFailure(t, "/admin/v1/members/_search", tc.status)
			r := newHumanAdminsTestReconciler(t, srv.URL)
			pb := humanAdminsCR(srv.URL)

			res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
			if err != nil {
				t.Fatalf("reconcileHumanAdminsScoped: %v", err)
			}
			if tc.wantRequeue != (res.RequeueAfter != 0) {
				t.Fatalf("result = %+v, wantRequeue=%v", res, tc.wantRequeue)
			}
			cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionHumanAdminsScoped)
			if cond == nil || cond.Reason != tc.wantReason {
				t.Fatalf("condition = %+v, want reason %s", cond, tc.wantReason)
			}
		})
	}
}

func TestReconcileHumanAdminsScoped_RemoveIAMMemberErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		wantReason  string
		wantRequeue bool
	}{
		{"permanent", http.StatusForbidden, "ZitadelPermanentError", false},
		{"transient", http.StatusInternalServerError, "ZitadelTransientError", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-1","name":"gibson"}]}`))
			})
			mux.HandleFunc("/management/v1/projects/PROJ-1", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"project":{"details":{"resourceOwner":"ORG-1"}}}`))
			})
			mux.HandleFunc("/admin/v1/members/_search", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(membersSearchBody([]iamMemberFixture{
					{UserID: "UID-ROGUE", PreferredLoginName: "rogue@example.com", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
				}))
			})
			mux.HandleFunc("/admin/v1/members/UID-ROGUE", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				if tc.status == http.StatusForbidden {
					_, _ = w.Write([]byte(`{"code":"permission_denied","message":"denied"}`))
				}
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			r := newHumanAdminsTestReconciler(t, srv.URL)
			pb := humanAdminsCR(srv.URL)

			res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
			if err != nil {
				t.Fatalf("reconcileHumanAdminsScoped: %v", err)
			}
			if tc.wantRequeue != (res.RequeueAfter != 0) {
				t.Fatalf("result = %+v, wantRequeue=%v", res, tc.wantRequeue)
			}
			cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionHumanAdminsScoped)
			if cond == nil || cond.Reason != tc.wantReason {
				t.Fatalf("condition = %+v, want reason %s", cond, tc.wantReason)
			}
		})
	}
}

func TestReconcileHumanAdminsScoped_DeleteUserErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		wantReason  string
		wantRequeue bool
	}{
		{"permanent", http.StatusForbidden, "ZitadelPermanentError", false},
		{"transient", http.StatusInternalServerError, "ZitadelTransientError", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-1","name":"gibson"}]}`))
			})
			mux.HandleFunc("/management/v1/projects/PROJ-1", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"project":{"details":{"resourceOwner":"ORG-1"}}}`))
			})
			mux.HandleFunc("/admin/v1/members/_search", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(membersSearchBody([]iamMemberFixture{
					{UserID: "UID-DEFAULT", PreferredLoginName: "zitadel-admin@zitadel.app.example.test", UserType: "TYPE_HUMAN", UserResourceOwner: "ORG-1"},
				}))
			})
			mux.HandleFunc("/admin/v1/members/UID-DEFAULT", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{}`))
			})
			mux.HandleFunc("/zitadel.user.v2.UserService/DeleteUser", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				if tc.status == http.StatusForbidden {
					_, _ = w.Write([]byte(`{"code":"permission_denied","message":"denied"}`))
				}
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			r := newHumanAdminsTestReconciler(t, srv.URL)
			pb := humanAdminsCR(srv.URL)

			res, err := r.reconcileHumanAdminsScoped(context.Background(), pb, logr.Discard())
			if err != nil {
				t.Fatalf("reconcileHumanAdminsScoped: %v", err)
			}
			if tc.wantRequeue != (res.RequeueAfter != 0) {
				t.Fatalf("result = %+v, wantRequeue=%v", res, tc.wantRequeue)
			}
			cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionHumanAdminsScoped)
			if cond == nil || cond.Reason != tc.wantReason {
				t.Fatalf("condition = %+v, want reason %s", cond, tc.wantReason)
			}
		})
	}
}

// TestIsDefaultFirstInstanceAdmin is a table test over the identification
// predicate directly, pinning every one of its three required signals.
func TestIsDefaultFirstInstanceAdmin(t *testing.T) {
	const orgID = "ORG-1"
	cases := []struct {
		name string
		m    zitadel.IAMMember
		want bool
	}{
		{"matches", zitadel.IAMMember{UserType: zitadel.ZitadelUserTypeHuman, UserResourceOwner: orgID, PreferredLoginName: "zitadel-admin@zitadel.example.test"}, true},
		{"machine, not human", zitadel.IAMMember{UserType: zitadel.ZitadelUserTypeMachine, UserResourceOwner: orgID, PreferredLoginName: "zitadel-admin@zitadel.example.test"}, false},
		{"different org", zitadel.IAMMember{UserType: zitadel.ZitadelUserTypeHuman, UserResourceOwner: "ORG-2", PreferredLoginName: "zitadel-admin@zitadel.example.test"}, false},
		{"different prefix", zitadel.IAMMember{UserType: zitadel.ZitadelUserTypeHuman, UserResourceOwner: orgID, PreferredLoginName: "owner@example.com"}, false},
		{"prefix substring but not anchored", zitadel.IAMMember{UserType: zitadel.ZitadelUserTypeHuman, UserResourceOwner: orgID, PreferredLoginName: "not-zitadel-admin@example.test"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isDefaultFirstInstanceAdmin(tc.m, orgID)
			if got != tc.want {
				t.Fatalf("isDefaultFirstInstanceAdmin(%+v) = %v, want %v", tc.m, got, tc.want)
			}
		})
	}
}
