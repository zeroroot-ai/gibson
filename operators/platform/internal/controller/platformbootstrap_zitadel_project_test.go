// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// fakeProjectRolesZitadelServer serves just enough of the Zitadel admin API
// for reconcileZitadelProject to run end to end: project creation/lookup,
// the v2 project-role calls EnsureProjectRoles issues, and the login-policy
// GET/PUT of EnsureRegistrationDisabled.
func fakeProjectRolesZitadelServer(t *testing.T, projectID string, roles map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id": projectID})
	})
	mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]string{{"id": projectID, "name": "gibson"}},
		})
	})
	mux.HandleFunc("/zitadel.project.v2.ProjectService/ListProjectRoles", func(w http.ResponseWriter, _ *http.Request) {
		type roleOut struct{ RoleKey, DisplayName string }
		out := make([]roleOut, 0, len(roles))
		for k, v := range roles {
			out = append(out, roleOut{RoleKey: k, DisplayName: v})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"roles": out})
	})
	mux.HandleFunc("/zitadel.project.v2.ProjectService/AddProjectRole", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ RoleKey, DisplayName string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		roles[req.RoleKey] = req.DisplayName
		_ = json.NewEncoder(w).Encode(map[string]any{})
	})
	mux.HandleFunc("/zitadel.project.v2.ProjectService/UpdateProjectRole", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ RoleKey, DisplayName string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		roles[req.RoleKey] = req.DisplayName
		_ = json.NewEncoder(w).Encode(map[string]any{})
	})
	mux.HandleFunc("/zitadel.project.v2.ProjectService/RemoveProjectRole", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ RoleKey string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		delete(roles, req.RoleKey)
		_ = json.NewEncoder(w).Encode(map[string]any{})
	})
	mux.HandleFunc("/admin/v1/policies/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{"policy": map[string]any{"allowRegister": false}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestPlatformBootstrap(ensureExists bool) *gibsonv1alpha1.PlatformBootstrap {
	return &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			Zitadel: gibsonv1alpha1.ZitadelSpec{
				Issuer:        "https://zitadel.example.invalid",
				AdminTokenRef: gibsonv1alpha1.SecretKeyRef{Name: "iam-admin-pat", Key: "pat"},
				Project:       gibsonv1alpha1.ZitadelProjectSpec{Name: "gibson", EnsureExists: ensureExists},
			},
		},
	}
}

func newReconcilerWithPAT(t *testing.T, zitadelURL string) *PlatformBootstrapReconciler {
	t.Helper()
	s := mustScheme(t)
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "iam-admin-pat", Namespace: defaultChildNamespace},
		Data:       map[string][]byte{"pat": []byte("test-pat")},
	}).Build()
	return &PlatformBootstrapReconciler{
		Client:   cli,
		Scheme:   s,
		Recorder: record.NewFakeRecorder(8),
		ZitadelFactory: func(_, pat string) zitadel.Client {
			return zitadel.New(zitadelURL, pat, "")
		},
	}
}

// TestReconcileZitadelProject_CallsEnsureProjectRolesOnTheEnsureExistsBranch
// pins that the project-roles step runs after EnsureProject (the
// EnsureExists=true branch) and that the projectID EnsureProject returns is
// the one passed to EnsureProjectRoles.
func TestReconcileZitadelProject_CallsEnsureProjectRolesOnTheEnsureExistsBranch(t *testing.T) {
	roles := map[string]string{}
	srv := fakeProjectRolesZitadelServer(t, "PROJ-777", roles)
	r := newReconcilerWithPAT(t, srv.URL)
	pb := newTestPlatformBootstrap(true)

	if _, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileZitadelProject: %v", err)
	}
	want := map[string]string{"owner": "Owner", "admin": "Admin", "editor": "Editor", "viewer": "Viewer"}
	if len(roles) != len(want) {
		t.Fatalf("roles = %v, want %v", roles, want)
	}
	for k, v := range want {
		if roles[k] != v {
			t.Errorf("roles[%q] = %q, want %q", k, roles[k], v)
		}
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionZitadelProjectReady)
	if c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("ZitadelProjectReady = %+v, want True", c)
	}
}

// TestReconcileZitadelProject_CallsEnsureProjectRolesOnTheLookupBranch pins
// the same behavior on the EnsureExists=false (GetProjectIDByName) branch.
func TestReconcileZitadelProject_CallsEnsureProjectRolesOnTheLookupBranch(t *testing.T) {
	roles := map[string]string{}
	srv := fakeProjectRolesZitadelServer(t, "PROJ-888", roles)
	r := newReconcilerWithPAT(t, srv.URL)
	pb := newTestPlatformBootstrap(false)

	if _, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileZitadelProject: %v", err)
	}
	if len(roles) != 4 {
		t.Fatalf("roles = %v, want 4 entries", roles)
	}
}

// TestReconcileZitadelProject_PermanentEnsureProjectRolesErrorSetsCondition
// pins that a permanent EnsureProjectRoles failure sets
// ZitadelPermanentError rather than looping the transient retry path.
func TestReconcileZitadelProject_PermanentEnsureProjectRolesErrorSetsCondition(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "PROJ-999"})
	})
	mux.HandleFunc("/zitadel.project.v2.ProjectService/ListProjectRoles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "permission_denied", "message": "Errors.PermissionDenied"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	r := newReconcilerWithPAT(t, srv.URL)
	pb := newTestPlatformBootstrap(true)

	if _, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileZitadelProject: %v", err)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionZitadelProjectReady)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != "ZitadelPermanentError" {
		t.Fatalf("ZitadelProjectReady = %+v, want False/ZitadelPermanentError", c)
	}
}

// TestReconcileZitadelProject_TransientEnsureProjectRolesErrorRequeues pins
// the other branch of the same error check: a non-permanent
// EnsureProjectRoles failure (here, a 500 from ListProjectRoles, which
// zitadel.IsPermanent does not classify as permanent — only 401/403 are)
// sets ZitadelTransientError with ConditionUnknown and asks for a requeue,
// rather than a hard failure like the permanent case above.
func TestReconcileZitadelProject_TransientEnsureProjectRolesErrorRequeues(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "PROJ-999"})
	})
	mux.HandleFunc("/zitadel.project.v2.ProjectService/ListProjectRoles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "internal", "message": "Errors.Internal"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	r := newReconcilerWithPAT(t, srv.URL)
	pb := newTestPlatformBootstrap(true)

	result, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelProject: %v", err)
	}
	if result.RequeueAfter <= 0 {
		t.Fatalf("result = %+v, want a positive RequeueAfter", result)
	}
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionZitadelProjectReady)
	if c == nil || c.Status != metav1.ConditionUnknown || c.Reason != "ZitadelTransientError" {
		t.Fatalf("ZitadelProjectReady = %+v, want Unknown/ZitadelTransientError", c)
	}
}
