// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

func baseSMTPCR(zitadelURL string) *gibsonv1alpha1.PlatformBootstrap {
	tlsOn := true
	return &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "platform"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			Zitadel: gibsonv1alpha1.ZitadelSpec{
				AdminTokenRef: gibsonv1alpha1.SecretKeyRef{Name: "iam-admin-pat", Namespace: "gibson", Key: "pat"},
				Project:       gibsonv1alpha1.ZitadelProjectSpec{Name: "gibson"},
				SMTP: &gibsonv1alpha1.ZitadelSMTPSpec{
					Host:        "email-smtp.us-east-1.amazonaws.com",
					Port:        587,
					FromAddress: "no-reply@staging.zeroroot.ai",
					FromName:    "Zero Root",
					TLS:         &tlsOn,
					UserSecretRef: &gibsonv1alpha1.SecretKeyRef{
						Name: "gibson-email-smtp", Namespace: "gibson", Key: "username",
					},
					PasswordSecretRef: &gibsonv1alpha1.SecretKeyRef{
						Name: "gibson-email-smtp", Namespace: "gibson", Key: "password",
					},
				},
			},
		},
	}
}

func smtpCredsSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "gibson-email-smtp", Namespace: "gibson"},
		Data:       map[string][]byte{"username": []byte("smtp-user"), "password": []byte("smtp-pass")},
	}
}

func newSMTPReconciler(t *testing.T, zitadelURL string, objs ...client.Object) *PlatformBootstrapReconciler {
	t.Helper()
	s := mustScheme(t)
	builder := fake.NewClientBuilder().WithScheme(s)
	if len(objs) > 0 {
		builder = builder.WithObjects(objs...)
	}
	cli := builder.Build()
	return &PlatformBootstrapReconciler{
		Audit:    (&audittest.Sink{}).Emitter(t),
		Client:   cli,
		Scheme:   s,
		Recorder: record.NewFakeRecorder(8),
		ZitadelFactory: func(_, pat string) zitadel.Client {
			return zitadel.New(zitadelURL, pat, "app.example.test")
		},
	}
}

// smtpMuxCounters is a set of call counters for asserting exactly which
// Zitadel email-provider endpoints a reconcile touched.
type smtpMuxCounters struct {
	search, add, update, activate, getByID int32
}

// smtpMux builds a fake Zitadel email-provider surface. existingID, when
// non-empty, makes the search + get-by-id endpoints answer as if that
// provider already exists with existingState (which the caller mutates to
// control drift/activation scenarios). getByIDStatus/searchStatus, when
// non-zero, override the corresponding endpoint's HTTP status for
// error-branch tests.
type smtpMux struct {
	existingID     string
	existingState  string // protojson state enum, e.g. EMAIL_PROVIDER_ACTIVE
	existingSMTP   string // raw protojson "smtp":{...} body, or "" for none
	getByIDStatus  int
	searchStatus   int
	addStatus      int
	addBody        string
	updateStatus   int
	activateStatus int
	counters       smtpMuxCounters
}

// handler builds a *http.ServeMux with one route per endpoint, registered
// against the concrete paths m.existingID resolves to (known up front, since
// every smtpMux is fully configured before its test server starts). This
// keeps each route's logic in its own small method instead of one large
// branch, matching the shape http.ServeMux itself expects.
func (m *smtpMux) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/v1/email/_search", m.handleSearch)
	mux.HandleFunc("POST /admin/v1/email/smtp", m.handleAdd)
	if m.existingID != "" {
		mux.HandleFunc("GET /admin/v1/email/"+m.existingID, m.handleGetByID)
		mux.HandleFunc("PUT /admin/v1/email/smtp/"+m.existingID, m.handleUpdate)
		mux.HandleFunc("POST /admin/v1/email/"+m.existingID+"/_activate", m.handleActivate)
	}
	mux.HandleFunc("POST /admin/v1/email/NEW-PROVIDER/_activate", m.handleActivate)
	return mux
}

func (m *smtpMux) handleGetByID(w http.ResponseWriter, _ *http.Request) {
	atomic.AddInt32(&m.counters.getByID, 1)
	if m.getByIDStatus != 0 {
		w.WriteHeader(m.getByIDStatus)
		return
	}
	smtp := "null"
	if m.existingSMTP != "" {
		smtp = m.existingSMTP
	}
	_, _ = w.Write([]byte(`{"config":{"id":"` + m.existingID + `","state":"` + m.existingState + `","smtp":` + smtp + `}}`))
}

func (m *smtpMux) handleSearch(w http.ResponseWriter, _ *http.Request) {
	atomic.AddInt32(&m.counters.search, 1)
	if m.searchStatus != 0 {
		w.WriteHeader(m.searchStatus)
		return
	}
	if m.existingID == "" {
		_, _ = w.Write([]byte(`{"result":[]}`))
		return
	}
	_, _ = w.Write([]byte(`{"result":[{"id":"` + m.existingID + `","description":"gibson-platform-operator"}]}`))
}

func (m *smtpMux) handleAdd(w http.ResponseWriter, _ *http.Request) {
	atomic.AddInt32(&m.counters.add, 1)
	if m.addStatus != 0 {
		w.WriteHeader(m.addStatus)
		return
	}
	body := m.addBody
	if body == "" {
		body = `{"id":"NEW-PROVIDER"}`
	}
	_, _ = w.Write([]byte(body))
}

func (m *smtpMux) handleUpdate(w http.ResponseWriter, _ *http.Request) {
	atomic.AddInt32(&m.counters.update, 1)
	if m.updateStatus != 0 {
		w.WriteHeader(m.updateStatus)
		return
	}
	_, _ = w.Write([]byte(`{"details":{}}`))
}

func (m *smtpMux) handleActivate(w http.ResponseWriter, _ *http.Request) {
	atomic.AddInt32(&m.counters.activate, 1)
	if m.activateStatus != 0 {
		w.WriteHeader(m.activateStatus)
		return
	}
	_, _ = w.Write([]byte(`{"details":{}}`))
}

func TestReconcileZitadelSMTP_NotConfigured_Skips(t *testing.T) {
	r := newSMTPReconciler(t, "http://unused.invalid")
	pb := baseSMTPCR("http://unused.invalid")
	pb.Spec.Zitadel.SMTP = nil

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSMTPProviderReady)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "NotConfigured" {
		t.Fatalf("condition = %+v, want True/NotConfigured", cond)
	}
}

func TestReconcileZitadelSMTP_WaitingForAdminToken(t *testing.T) {
	r := newSMTPReconciler(t, "http://unused.invalid")
	pb := baseSMTPCR("http://unused.invalid")

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue while waiting for the admin token Secret")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSMTPProviderReady)
	if cond == nil || cond.Reason != "WaitingForAdminToken" {
		t.Fatalf("condition = %+v, want reason WaitingForAdminToken", cond)
	}
}

func TestReconcileZitadelSMTP_WaitingForCredentialsSecret(t *testing.T) {
	r := newSMTPReconciler(t, "http://unused.invalid", adminPATSecret())
	pb := baseSMTPCR("http://unused.invalid")
	// gibson-email-smtp Secret intentionally not created.

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("expected a requeue while waiting for the credentials Secret")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSMTPProviderReady)
	if cond == nil || cond.Reason != "WaitingForCredentialsSecret" {
		t.Fatalf("condition = %+v, want reason WaitingForCredentialsSecret", cond)
	}
}

func TestReconcileZitadelSMTP_MissingPasswordSecretRef(t *testing.T) {
	r := newSMTPReconciler(t, "http://unused.invalid", adminPATSecret(), smtpCredsSecret())
	pb := baseSMTPCR("http://unused.invalid")
	pb.Spec.Zitadel.SMTP.PasswordSecretRef = nil

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero (permanent misconfiguration)", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSMTPProviderReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "MissingPasswordSecretRef" {
		t.Fatalf("condition = %+v, want False/MissingPasswordSecretRef", cond)
	}
}

func TestReconcileZitadelSMTP_FirstReconcile_CreatesAndActivates(t *testing.T) {
	m := &smtpMux{}
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	r := newSMTPReconciler(t, srv.URL, adminPATSecret(), smtpCredsSecret())
	pb := baseSMTPCR(srv.URL)

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSMTPProviderReady)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "ProviderActive" {
		t.Fatalf("condition = %+v, want True/ProviderActive", cond)
	}
	if pb.Status.SMTPProviderID != "NEW-PROVIDER" {
		t.Fatalf("SMTPProviderID = %q, want NEW-PROVIDER", pb.Status.SMTPProviderID)
	}
	if pb.Status.SMTPSettingsHash == "" {
		t.Fatal("SMTPSettingsHash was not persisted")
	}
	if m.counters.add != 1 || m.counters.activate != 1 {
		t.Fatalf("counters = %+v, want add=1 activate=1", m.counters)
	}
}

func TestReconcileZitadelSMTP_SteadyState_NoOp(t *testing.T) {
	m := &smtpMux{
		existingID:    "PROVIDER-1",
		existingState: "EMAIL_PROVIDER_ACTIVE",
		existingSMTP:  `{"senderAddress":"no-reply@staging.zeroroot.ai","senderName":"Zero Root","tls":true,"host":"email-smtp.us-east-1.amazonaws.com:587","user":"smtp-user","replyToAddress":""}`,
	}
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	r := newSMTPReconciler(t, srv.URL, adminPATSecret(), smtpCredsSecret())
	pb := baseSMTPCR(srv.URL)
	pb.Status.SMTPProviderID = "PROVIDER-1"
	// The hash of the exact settings the mux + creds Secret above resolve
	// to; a real reconcile computes this from the live spec, so a matching
	// stored hash represents "nothing has changed since the last reconcile."
	pb.Status.SMTPSettingsHash = smtpSettingsHash(pb.Spec.Zitadel.SMTP, "smtp-user", "smtp-pass")

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	if m.counters.add != 0 || m.counters.update != 0 || m.counters.activate != 0 {
		t.Fatalf("counters = %+v, want no Add/Update/Activate calls on a steady-state reconcile", m.counters)
	}
	if m.counters.getByID != 1 {
		t.Fatalf("getByID calls = %d, want 1", m.counters.getByID)
	}
}

func TestReconcileZitadelSMTP_DriftRepair_UpdatesAndActivates(t *testing.T) {
	m := &smtpMux{
		existingID:    "PROVIDER-1",
		existingState: "EMAIL_PROVIDER_INACTIVE", // drifted: not active
		existingSMTP:  `{"senderAddress":"no-reply@staging.zeroroot.ai","senderName":"Zero Root","tls":true,"host":"OLD-HOST:587","user":"smtp-user"}`,
	}
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	r := newSMTPReconciler(t, srv.URL, adminPATSecret(), smtpCredsSecret())
	pb := baseSMTPCR(srv.URL)
	pb.Status.SMTPProviderID = "PROVIDER-1"

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	if m.counters.add != 0 {
		t.Fatalf("add calls = %d, want 0 (the provider already exists)", m.counters.add)
	}
	if m.counters.update != 1 {
		t.Fatalf("update calls = %d, want 1 (host drifted)", m.counters.update)
	}
	if m.counters.activate != 1 {
		t.Fatalf("activate calls = %d, want 1 (provider was inactive)", m.counters.activate)
	}
}

func TestReconcileZitadelSMTP_PasswordOnlyChange_UpdatesWithoutReactivating(t *testing.T) {
	m := &smtpMux{
		existingID:    "PROVIDER-1",
		existingState: "EMAIL_PROVIDER_ACTIVE",
		existingSMTP:  `{"senderAddress":"no-reply@staging.zeroroot.ai","senderName":"Zero Root","tls":true,"host":"email-smtp.us-east-1.amazonaws.com:587","user":"smtp-user"}`,
	}
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	r := newSMTPReconciler(t, srv.URL, adminPATSecret(), smtpCredsSecret())
	pb := baseSMTPCR(srv.URL)
	pb.Status.SMTPProviderID = "PROVIDER-1"
	// A hash that does NOT match the current (host/user-identical) settings,
	// simulating a rotated password Zitadel cannot echo back.
	pb.Status.SMTPSettingsHash = "stale-hash-from-a-previous-password"

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	if m.counters.update != 1 {
		t.Fatalf("update calls = %d, want 1 (password hash mismatch must still update)", m.counters.update)
	}
	if m.counters.activate != 0 {
		t.Fatalf("activate calls = %d, want 0 (provider was already active)", m.counters.activate)
	}
	if pb.Status.SMTPSettingsHash != smtpSettingsHash(pb.Spec.Zitadel.SMTP, "smtp-user", "smtp-pass") {
		t.Fatal("SMTPSettingsHash was not refreshed after the update")
	}
}

func TestReconcileZitadelSMTP_StaleIDRecoversByDescription(t *testing.T) {
	m := &smtpMux{
		existingID:    "PROVIDER-1",
		existingState: "EMAIL_PROVIDER_ACTIVE",
		existingSMTP:  `{"senderAddress":"no-reply@staging.zeroroot.ai","senderName":"Zero Root","tls":true,"host":"email-smtp.us-east-1.amazonaws.com:587","user":"smtp-user"}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/email/STALE-ID", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.Handle("/", m.handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	r := newSMTPReconciler(t, srv.URL, adminPATSecret(), smtpCredsSecret())
	pb := baseSMTPCR(srv.URL)
	pb.Status.SMTPProviderID = "STALE-ID"
	pb.Status.SMTPSettingsHash = smtpSettingsHash(pb.Spec.Zitadel.SMTP, "smtp-user", "smtp-pass")

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	if pb.Status.SMTPProviderID != "PROVIDER-1" {
		t.Fatalf("SMTPProviderID = %q, want the recovered PROVIDER-1", pb.Status.SMTPProviderID)
	}
	if m.counters.add != 0 {
		t.Fatalf("add calls = %d, want 0 (recovered via description search)", m.counters.add)
	}
}

func TestReconcileZitadelSMTP_ZitadelErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mux         func() *smtpMux
		statusField func(m *smtpMux, status int)
		wantReason  string
		wantRequeue bool
	}{
		{
			name: "GetSMTPEmailProviderState transient",
			mux: func() *smtpMux {
				return &smtpMux{existingID: "PROVIDER-1", existingState: "EMAIL_PROVIDER_ACTIVE", getByIDStatus: http.StatusInternalServerError}
			},
			wantReason:  "ZitadelTransientError",
			wantRequeue: true,
		},
		{
			name: "GetSMTPEmailProviderState permanent",
			mux: func() *smtpMux {
				return &smtpMux{existingID: "PROVIDER-1", existingState: "EMAIL_PROVIDER_ACTIVE", getByIDStatus: http.StatusForbidden}
			},
			wantReason:  "ZitadelPermanentError",
			wantRequeue: false,
		},
		{
			name: "FindSMTPEmailProviderByDescription transient",
			mux: func() *smtpMux {
				return &smtpMux{searchStatus: http.StatusInternalServerError}
			},
			wantReason:  "ZitadelTransientError",
			wantRequeue: true,
		},
		{
			name: "FindSMTPEmailProviderByDescription permanent",
			mux: func() *smtpMux {
				return &smtpMux{searchStatus: http.StatusForbidden}
			},
			wantReason:  "ZitadelPermanentError",
			wantRequeue: false,
		},
		{
			name: "AddSMTPEmailProvider transient",
			mux: func() *smtpMux {
				return &smtpMux{addStatus: http.StatusInternalServerError}
			},
			wantReason:  "ZitadelTransientError",
			wantRequeue: true,
		},
		{
			name: "AddSMTPEmailProvider permanent",
			mux: func() *smtpMux {
				return &smtpMux{addStatus: http.StatusForbidden}
			},
			wantReason:  "ZitadelPermanentError",
			wantRequeue: false,
		},
		{
			name: "ActivateEmailProvider transient on a freshly created provider",
			mux: func() *smtpMux {
				return &smtpMux{activateStatus: http.StatusInternalServerError}
			},
			wantReason:  "ZitadelTransientError",
			wantRequeue: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.mux()
			srv := httptest.NewServer(m.handler())
			t.Cleanup(srv.Close)
			r := newSMTPReconciler(t, srv.URL, adminPATSecret(), smtpCredsSecret())
			pb := baseSMTPCR(srv.URL)
			if m.existingID != "" {
				pb.Status.SMTPProviderID = m.existingID
			}

			res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
			if err != nil {
				t.Fatalf("reconcileZitadelSMTP: %v", err)
			}
			if tc.wantRequeue != (res.RequeueAfter != 0) {
				t.Fatalf("result = %+v, wantRequeue=%v", res, tc.wantRequeue)
			}
			cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSMTPProviderReady)
			if cond == nil || cond.Reason != tc.wantReason {
				t.Fatalf("condition = %+v, want reason %s", cond, tc.wantReason)
			}
		})
	}
}

func TestReconcileZitadelSMTP_UpdateSMTPEmailProviderError(t *testing.T) {
	m := &smtpMux{
		existingID:    "PROVIDER-1",
		existingState: "EMAIL_PROVIDER_ACTIVE",
		existingSMTP:  `{"host":"DRIFTED:587"}`,
		updateStatus:  http.StatusForbidden,
	}
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	r := newSMTPReconciler(t, srv.URL, adminPATSecret(), smtpCredsSecret())
	pb := baseSMTPCR(srv.URL)
	pb.Status.SMTPProviderID = "PROVIDER-1"

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero (permanent)", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSMTPProviderReady)
	if cond == nil || cond.Reason != "ZitadelPermanentError" {
		t.Fatalf("condition = %+v, want reason ZitadelPermanentError", cond)
	}
}

func TestReconcileZitadelSMTP_NoAuth(t *testing.T) {
	m := &smtpMux{}
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	r := newSMTPReconciler(t, srv.URL, adminPATSecret())
	pb := baseSMTPCR(srv.URL)
	pb.Spec.Zitadel.SMTP.UserSecretRef = nil
	pb.Spec.Zitadel.SMTP.PasswordSecretRef = nil

	res, err := r.reconcileZitadelSMTP(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelSMTP: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("result = %+v, want zero", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionSMTPProviderReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("condition = %+v, want True", cond)
	}
}

// TestSMTPSettingsHash_IsStableAndChangesWithEachField: the fingerprint is the
// same for the same settings, changes when the password or any other field
// changes, and never holds the password or a fast hash of it.
func TestSMTPSettingsHash_IsStableAndChangesWithEachField(t *testing.T) {
	type settings struct {
		spec           gibsonv1alpha1.ZitadelSMTPSpec
		user, password string
	}
	tlsOn, tlsOff := true, false
	base := settings{
		spec:     gibsonv1alpha1.ZitadelSMTPSpec{FromAddress: "noreply@example.com", FromName: "Gibson", TLS: &tlsOn, Host: "smtp.example.com", Port: 587},
		user:     "smtp-user",
		password: "smtp-pass",
	}
	hash := func(s settings) string { return smtpSettingsHash(&s.spec, s.user, s.password) }
	got := hash(base)
	if got != hash(base) {
		t.Fatal("the fingerprint of one set of settings must be stable")
	}
	for name, change := range map[string]func(*settings){
		"password": func(s *settings) { s.password = "other-pass" },
		"host":     func(s *settings) { s.spec.Host = "smtp.other.com" },
		"user":     func(s *settings) { s.user = "other-user" },
		"tls":      func(s *settings) { s.spec.TLS = &tlsOff },
	} {
		c := base
		change(&c)
		if hash(c) == got {
			t.Errorf("a change of the %s must change the fingerprint", name)
		}
	}
	fast := sha256.Sum256([]byte(base.password))
	if strings.Contains(got, base.password) || strings.Contains(got, hex.EncodeToString(fast[:])) {
		t.Fatal("the fingerprint must hold neither the password nor a fast hash of it")
	}
}
