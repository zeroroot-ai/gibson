// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	fgaclient "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/fga"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// fakeFGAServer is a minimal in-memory OpenFGA Check/Write fake, scoped to
// exactly what reconcilePlatformOwner's WriteTuple call needs: it is not the
// shared zitadelconntest fake (that fakes Zitadel, not OpenFGA).
type fakeFGAServer struct {
	mu     sync.Mutex
	tuples map[string]bool // "user|relation|object" -> true
}

func newFakeFGAServer() *httptest.Server {
	f := &fakeFGAServer{tuples: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/stores/gibson-store/check", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			TupleKey struct {
				User     string `json:"user"`
				Relation string `json:"relation"`
				Object   string `json:"object"`
			} `json:"tuple_key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		allowed := f.tuples[req.TupleKey.User+"|"+req.TupleKey.Relation+"|"+req.TupleKey.Object]
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]bool{"allowed": allowed})
	})
	mux.HandleFunc("/stores/gibson-store/write", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Writes struct {
				TupleKeys []struct {
					User     string `json:"user"`
					Relation string `json:"relation"`
					Object   string `json:"object"`
				} `json:"tuple_keys"`
			} `json:"writes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		for _, tk := range req.Writes.TupleKeys {
			f.tuples[tk.User+"|"+tk.Relation+"|"+tk.Object] = true
		}
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	})
	return httptest.NewServer(mux)
}

// zitadelOwnerMux builds the fake Zitadel handler for the endpoints
// reconcilePlatformOwner drives. userExists seeds AddHumanUser to answer 409
// (already exists) so the idempotent-lookup branch is exercised.
func zitadelOwnerMux(t *testing.T, userExists bool, factorTypes string) (*httptest.Server, *int32) {
	t.Helper()
	var clearFactorCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-1","name":"gibson"}]}`))
	})
	mux.HandleFunc("/management/v1/projects/PROJ-1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"project":{"details":{"resourceOwner":"ORG-1"}}}`))
	})
	mux.HandleFunc("/zitadel.user.v2.UserService/AddHumanUser", func(w http.ResponseWriter, r *http.Request) {
		if userExists {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":"already_exists","message":"exists"}`))
			return
		}
		_, _ = w.Write([]byte(`{"userId":"UID-OWNER"}`))
	})
	mux.HandleFunc("/zitadel.user.v2.UserService/ListUsers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":[{"userId":"UID-OWNER"}]}`))
	})
	mux.HandleFunc("/admin/v1/members", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/zitadel.user.v2.UserService/CreateInviteCode", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "returnCode") {
			_, _ = w.Write([]byte(`{"inviteCode":"CODE-XYZ"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/zitadel.user.v2.UserService/ListAuthenticationMethodTypes", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"authMethodTypes":[` + factorTypes + `]}`))
	})
	mux.HandleFunc("/zitadel.user.v2.UserService/RemoveTOTP", func(w http.ResponseWriter, r *http.Request) {
		clearFactorCalls++
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &clearFactorCalls
}

func basePlatformOwnerCR(zitadelURL string) *gibsonv1alpha1.PlatformBootstrap {
	return &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "platform"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			Zitadel: gibsonv1alpha1.ZitadelSpec{
				Issuer:        zitadelURL,
				AdminTokenRef: gibsonv1alpha1.SecretKeyRef{Name: "iam-admin-pat", Namespace: "gibson", Key: "pat"},
				Project:       gibsonv1alpha1.ZitadelProjectSpec{Name: "gibson"},
			},
			FGAModel: gibsonv1alpha1.FGAModelSpec{
				StoreNameRef: gibsonv1alpha1.SecretKeyRef{Name: "gibson-fga-config", Namespace: "gibson", Key: "store_id"},
			},
		},
	}
}

func newOwnerTestReconciler(t *testing.T, zitadelURL, fgaURL string, objs ...client.Object) *PlatformBootstrapReconciler {
	t.Helper()
	s := mustScheme(t)
	builder := fake.NewClientBuilder().WithScheme(s)
	if len(objs) > 0 {
		builder = builder.WithObjects(objs...)
	}
	cli := builder.Build()
	return &PlatformBootstrapReconciler{
		Client:   cli,
		Scheme:   s,
		Recorder: record.NewFakeRecorder(8),
		ZitadelFactory: func(issuer, pat string) zitadel.Client {
			return zitadel.New(zitadelURL, pat, "")
		},
		FGAFactory: func(apiEndpoint string) (fgaclient.Client, error) {
			return fgaclient.New(fgaURL)
		},
	}
}

func adminPATSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "iam-admin-pat", Namespace: "gibson"},
		Data:       map[string][]byte{"pat": []byte("fake-pat")},
	}
}

func fgaStoreSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "gibson-fga-config", Namespace: "gibson"},
		Data:       map[string][]byte{"store_id": []byte("gibson-store"), "model_id": []byte("MODEL-1")},
	}
}

func TestReconcilePlatformOwner_NotConfigured_Skips(t *testing.T) {
	r := newOwnerTestReconciler(t, "http://unused.invalid", "http://unused.invalid")
	pb := basePlatformOwnerCR("http://unused.invalid")
	// spec.platformOwner.email left empty.

	res, err := r.reconcilePlatformOwner(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcilePlatformOwner: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero (no requeue when not configured)", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPlatformOwnerReady)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "NotConfigured" {
		t.Fatalf("condition = %+v, want True/NotConfigured", cond)
	}
}

func TestReconcilePlatformOwner_WaitingForAdminToken(t *testing.T) {
	r := newOwnerTestReconciler(t, "http://unused.invalid", "http://unused.invalid")
	pb := basePlatformOwnerCR("http://unused.invalid")
	pb.Spec.PlatformOwner.Email = "owner@example.com"

	res, err := r.reconcilePlatformOwner(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcilePlatformOwner: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue while waiting for the admin token Secret")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPlatformOwnerReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "WaitingForAdminToken" {
		t.Fatalf("condition = %+v, want False/WaitingForAdminToken", cond)
	}
}

func TestReconcilePlatformOwner_WaitingForFGAModel(t *testing.T) {
	zsrv, _ := zitadelOwnerMux(t, false, "")
	r := newOwnerTestReconciler(t, zsrv.URL, "http://unused.invalid", adminPATSecret())
	pb := basePlatformOwnerCR(zsrv.URL)
	pb.Spec.PlatformOwner.Email = "owner@example.com"

	res, err := r.reconcilePlatformOwner(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcilePlatformOwner: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue while waiting for the FGA store Secret")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPlatformOwnerReady)
	if cond == nil || cond.Reason != "WaitingForFGAModel" {
		t.Fatalf("condition = %+v, want reason WaitingForFGAModel", cond)
	}
	// The user must already have been created (and its id persisted) even
	// though FGA isn't ready yet — the next reconcile must not create it
	// again.
	if pb.Status.PlatformOwnerUserID != "UID-OWNER" {
		t.Fatalf("PlatformOwnerUserID = %q, want UID-OWNER to already be persisted", pb.Status.PlatformOwnerUserID)
	}
}

func TestReconcilePlatformOwner_FirstReconcile_SendsInviteEmail(t *testing.T) {
	zsrv, _ := zitadelOwnerMux(t, false, "")
	fgaSrv := newFakeFGAServer()
	t.Cleanup(fgaSrv.Close)
	r := newOwnerTestReconciler(t, zsrv.URL, fgaSrv.URL, adminPATSecret(), fgaStoreSecret())
	pb := basePlatformOwnerCR(zsrv.URL)
	pb.Spec.PlatformOwner.Email = "owner@example.com"

	res, err := r.reconcilePlatformOwner(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcilePlatformOwner: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero (fully reconciled)", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPlatformOwnerReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("condition = %+v, want True", cond)
	}
	if pb.Status.PlatformOwnerUserID != "UID-OWNER" {
		t.Fatalf("PlatformOwnerUserID = %q, want UID-OWNER", pb.Status.PlatformOwnerUserID)
	}
	if pb.Status.ObservedSetupGeneration != 0 {
		t.Fatalf("ObservedSetupGeneration = %d, want 0 (spec left at default)", pb.Status.ObservedSetupGeneration)
	}
}

func TestReconcilePlatformOwner_OfflineSetup_WritesLinkSecret(t *testing.T) {
	zsrv, _ := zitadelOwnerMux(t, false, "")
	fgaSrv := newFakeFGAServer()
	t.Cleanup(fgaSrv.Close)
	r := newOwnerTestReconciler(t, zsrv.URL, fgaSrv.URL, adminPATSecret(), fgaStoreSecret())
	pb := basePlatformOwnerCR(zsrv.URL)
	pb.Spec.PlatformOwner.Email = "owner@example.com"
	pb.Spec.PlatformOwner.OfflineSetup = true
	pb.Spec.PlatformOwner.SetupSecretRef = &gibsonv1alpha1.SecretKeyRef{Name: "platform-owner-setup", Namespace: "gibson"}

	if _, err := r.reconcilePlatformOwner(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcilePlatformOwner: %v", err)
	}

	var sec corev1.Secret
	if err := r.Get(context.Background(), client.ObjectKey{Namespace: "gibson", Name: "platform-owner-setup"}, &sec); err != nil {
		t.Fatalf("setup link secret not written: %v", err)
	}
	link := string(sec.Data[defaultSetupSecretKey])
	for _, want := range []string{"UID-OWNER", "ORG-1", "CODE-XYZ"} {
		if !strings.Contains(link, want) {
			t.Fatalf("setup link %q missing %q", link, want)
		}
	}
}

func TestReconcilePlatformOwner_OfflineSetup_MissingSecretRef_Fails(t *testing.T) {
	zsrv, _ := zitadelOwnerMux(t, false, "")
	fgaSrv := newFakeFGAServer()
	t.Cleanup(fgaSrv.Close)
	r := newOwnerTestReconciler(t, zsrv.URL, fgaSrv.URL, adminPATSecret(), fgaStoreSecret())
	pb := basePlatformOwnerCR(zsrv.URL)
	pb.Spec.PlatformOwner.Email = "owner@example.com"
	pb.Spec.PlatformOwner.OfflineSetup = true
	// SetupSecretRef left nil.

	if _, err := r.reconcilePlatformOwner(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcilePlatformOwner: %v", err)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPlatformOwnerReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "MissingSetupSecretRef" {
		t.Fatalf("condition = %+v, want False/MissingSetupSecretRef", cond)
	}
}

// TestReconcilePlatformOwner_SetupGenerationBump_ClearsFactorsAndSendsNewLink
// pins ADR-0093 decision 12: raising setupGeneration on an EXISTING Platform
// owner clears every factor on file and mints a new link, without
// re-creating the user.
func TestReconcilePlatformOwner_SetupGenerationBump_ClearsFactorsAndSendsNewLink(t *testing.T) {
	zsrv, clearCalls := zitadelOwnerMux(t, true /* AddHumanUser answers already-exists */, `"AUTHENTICATION_METHOD_TYPE_TOTP"`)
	fgaSrv := newFakeFGAServer()
	t.Cleanup(fgaSrv.Close)
	r := newOwnerTestReconciler(t, zsrv.URL, fgaSrv.URL, adminPATSecret(), fgaStoreSecret())
	pb := basePlatformOwnerCR(zsrv.URL)
	pb.Spec.PlatformOwner.Email = "owner@example.com"
	pb.Spec.PlatformOwner.SetupGeneration = 1
	// Simulate a Platform owner already provisioned by an earlier reconcile.
	pb.Status.PlatformOwnerUserID = "UID-OWNER"
	pb.Status.ObservedSetupGeneration = 0

	if _, err := r.reconcilePlatformOwner(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcilePlatformOwner: %v", err)
	}
	if *clearCalls != 1 {
		t.Fatalf("RemoveTOTP called %d times, want 1 (setupGeneration bump must clear factors)", *clearCalls)
	}
	if pb.Status.ObservedSetupGeneration != 1 {
		t.Fatalf("ObservedSetupGeneration = %d, want 1", pb.Status.ObservedSetupGeneration)
	}
}

// TestReconcilePlatformOwner_SameGeneration_NoNewLink pins the steady-state
// no-op: a reconcile that finds the current generation already observed
// sends no new link and clears no factors.
func TestReconcilePlatformOwner_SameGeneration_NoNewLink(t *testing.T) {
	var inviteCalls int32
	zsrv, _ := zitadelOwnerMux(t, true, "")
	// Wrap: count whether CreateInviteCode is ever hit.
	origHandler := zsrv.Config.Handler
	zsrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/zitadel.user.v2.UserService/CreateInviteCode" {
			inviteCalls++
		}
		origHandler.ServeHTTP(w, r)
	})
	fgaSrv := newFakeFGAServer()
	t.Cleanup(fgaSrv.Close)
	r := newOwnerTestReconciler(t, zsrv.URL, fgaSrv.URL, adminPATSecret(), fgaStoreSecret())
	pb := basePlatformOwnerCR(zsrv.URL)
	pb.Spec.PlatformOwner.Email = "owner@example.com"
	pb.Spec.PlatformOwner.SetupGeneration = 2
	pb.Status.PlatformOwnerUserID = "UID-OWNER"
	pb.Status.ObservedSetupGeneration = 2

	if _, err := r.reconcilePlatformOwner(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcilePlatformOwner: %v", err)
	}
	if inviteCalls != 0 {
		t.Fatalf("CreateInviteCode called %d times, want 0 (generation already observed)", inviteCalls)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPlatformOwnerReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("condition = %+v, want True", cond)
	}
}

func TestReconcilePlatformOwner_ZitadelPermanentError_OnCreateUser(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/management/v1/projects/_search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":[{"id":"PROJ-1","name":"gibson"}]}`))
	})
	mux.HandleFunc("/management/v1/projects/PROJ-1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"project":{"details":{"resourceOwner":"ORG-1"}}}`))
	})
	mux.HandleFunc("/zitadel.user.v2.UserService/AddHumanUser", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"permission_denied","message":"denied"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	r := newOwnerTestReconciler(t, srv.URL, "http://unused.invalid", adminPATSecret())
	pb := basePlatformOwnerCR(srv.URL)
	pb.Spec.PlatformOwner.Email = "owner@example.com"

	res, err := r.reconcilePlatformOwner(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcilePlatformOwner: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero (permanent errors do not requeue)", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionPlatformOwnerReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "ZitadelPermanentError" {
		t.Fatalf("condition = %+v, want False/ZitadelPermanentError", cond)
	}
}
