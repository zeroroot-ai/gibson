// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// labelState is one copy of the label policy: its fields and its marks
// (policy field -> served bytes).
type labelState struct {
	fields map[string]any
	marks  map[string][]byte
}

func (s labelState) clone() labelState {
	return labelState{fields: maps.Clone(s.fields), marks: maps.Clone(s.marks)}
}

// fakeLabelZitadel models the two copies Zitadel keeps: every write changes
// the preview, and only _activate copies the preview to the active policy
// that GET returns and the login pages serve. A PUT that changes nothing is
// refused with 400, as Zitadel does.
type fakeLabelZitadel struct {
	mu       sync.Mutex
	srv      *httptest.Server
	preview  labelState
	active   labelState
	served   map[string][]byte // asset path -> bytes
	uploads  int
	puts     int
	activate int
	// fail makes one path answer 500.
	fail string
	// ignoreActivate makes _activate answer 200 and change nothing.
	ignoreActivate bool
	// failAssets makes every served mark answer 500.
	failAssets bool
}

var uploadField = map[string]string{
	"/assets/v1/instance/policy/label/logo":      "logoUrl",
	"/assets/v1/instance/policy/label/logo/dark": "logoUrlDark",
	"/assets/v1/instance/policy/label/icon":      "iconUrl",
	"/assets/v1/instance/policy/label/icon/dark": "iconUrlDark",
}

var removeField = map[string]string{
	"/admin/v1/policies/label/logo":      "logoUrl",
	"/admin/v1/policies/label/logo_dark": "logoUrlDark",
	"/admin/v1/policies/label/icon":      "iconUrl",
	"/admin/v1/policies/label/icon_dark": "iconUrlDark",
}

func newFakeLabelZitadel(t *testing.T) *fakeLabelZitadel {
	t.Helper()
	stock := labelState{fields: map[string]any{"primaryColor": "#5469d4", "hideLoginNameSuffix": false}, marks: map[string][]byte{}}
	f := &fakeLabelZitadel{preview: stock.clone(), active: stock.clone(), served: map[string][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLabelZitadel) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == f.fail {
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
		return
	}
	switch {
	case r.URL.Path == "/admin/v1/policies/label" && r.Method == http.MethodGet:
		out := maps.Clone(f.active.fields)
		for field, b := range f.active.marks {
			path := fmt.Sprintf("/assets/v1/inst/policy/label/%s-%d", field, len(f.served))
			f.served[path] = b
			out[field] = "https://app.example.test" + path
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"policy": out})
	case r.URL.Path == "/admin/v1/policies/label" && r.Method == http.MethodPut:
		f.puts++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if policyMatches(f.preview.fields, body) {
			http.Error(w, `{"code":9,"message":"Label Policy has not been changed"}`, http.StatusBadRequest)
			return
		}
		maps.Copy(f.preview.fields, body)
		_ = json.NewEncoder(w).Encode(map[string]any{})
	case r.URL.Path == "/admin/v1/policies/label/_activate":
		f.activate++
		if !f.ignoreActivate {
			f.active = f.preview.clone()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{})
	case removeField[r.URL.Path] != "" && r.Method == http.MethodDelete:
		field := removeField[r.URL.Path]
		if _, ok := f.preview.marks[field]; !ok {
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		delete(f.preview.marks, field)
	case uploadField[r.URL.Path] != "" && r.Method == http.MethodPost:
		f.uploads++
		file, _, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b, _ := io.ReadAll(file)
		f.preview.marks[uploadField[r.URL.Path]] = b
	case strings.HasPrefix(r.URL.Path, "/assets/v1/inst/"):
		if f.failAssets {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		b, ok := f.served[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
	}
}

func (f *fakeLabelZitadel) client() zitadel.Client { return zitadel.New(f.srv.URL, "test-pat", "") }

func testBrand() brand {
	return brand{
		policy: map[string]any{"primaryColor": "#346000", "hideLoginNameSuffix": true, "themeMode": "THEME_MODE_LIGHT"},
		logo:   []byte("<svg>logo</svg>"),
		icon:   []byte("<svg>icon</svg>"),
	}
}

func assertActiveBrand(t *testing.T, f *fakeLabelZitadel, b brand) {
	t.Helper()
	if !policyMatches(f.active.fields, b.policy) {
		t.Errorf("active fields = %v, want %v", f.active.fields, b.policy)
	}
	for _, slot := range zitadel.LabelSlots {
		if got := string(f.active.marks[slot.Field]); got != string(b.mark(slot)) {
			t.Errorf("active %s = %q, want %q", slot.Field, got, b.mark(slot))
		}
	}
}

func TestApplyLoginBranding_BrandsAStockInstance(t *testing.T) {
	f := newFakeLabelZitadel(t)
	changed, err := applyLoginBranding(context.Background(), f.client(), testBrand())
	if err != nil || !changed {
		t.Fatalf("applyLoginBranding = %v, %v; want changed", changed, err)
	}
	assertActiveBrand(t, f, testBrand())
	if f.uploads != 4 || f.activate != 1 {
		t.Errorf("uploads=%d activate=%d, want 4 and 1", f.uploads, f.activate)
	}
}

func TestApplyLoginBranding_SteadyStateWritesNothing(t *testing.T) {
	f := newFakeLabelZitadel(t)
	if _, err := applyLoginBranding(context.Background(), f.client(), testBrand()); err != nil {
		t.Fatal(err)
	}
	puts, uploads, activate := f.puts, f.uploads, f.activate
	changed, err := applyLoginBranding(context.Background(), f.client(), testBrand())
	if err != nil || changed {
		t.Fatalf("second apply = %v, %v; want unchanged", changed, err)
	}
	if f.puts != puts || f.uploads != uploads || f.activate != activate {
		t.Errorf("a steady-state apply wrote: puts %d->%d uploads %d->%d activate %d->%d",
			puts, f.puts, uploads, f.uploads, activate, f.activate)
	}
}

// TestApplyLoginBranding_ReplacesAChangedMarkByContent: a slot that serves
// other bytes is replaced; a slot that serves the right bytes is left alone.
func TestApplyLoginBranding_ReplacesAChangedMarkByContent(t *testing.T) {
	f := newFakeLabelZitadel(t)
	if _, err := applyLoginBranding(context.Background(), f.client(), testBrand()); err != nil {
		t.Fatal(err)
	}
	b := testBrand()
	b.logo = []byte("<svg>new logo</svg>")
	uploads, puts := f.uploads, f.puts
	changed, err := applyLoginBranding(context.Background(), f.client(), b)
	if err != nil || !changed {
		t.Fatalf("apply = %v, %v; want changed", changed, err)
	}
	if f.uploads-uploads != 2 {
		t.Errorf("uploads = %d, want 2 (the two logo slots)", f.uploads-uploads)
	}
	if f.puts != puts {
		t.Errorf("the policy fields did not change, but a PUT was sent")
	}
	assertActiveBrand(t, f, b)
}

// TestApplyLoginBranding_ActivatesAWrittenButInactivePreview covers a run
// that wrote the preview and stopped before activating: the PUT answers 400
// "not changed", and the step still activates.
func TestApplyLoginBranding_ActivatesAWrittenButInactivePreview(t *testing.T) {
	f := newFakeLabelZitadel(t)
	b := testBrand()
	maps.Copy(f.preview.fields, b.policy)
	for _, slot := range zitadel.LabelSlots {
		f.active.marks[slot.Field] = b.mark(slot)
		f.preview.marks[slot.Field] = b.mark(slot)
	}
	changed, err := applyLoginBranding(context.Background(), f.client(), b)
	if err != nil || !changed {
		t.Fatalf("apply = %v, %v; want changed", changed, err)
	}
	if f.activate != 1 {
		t.Errorf("activate = %d, want 1", f.activate)
	}
	assertActiveBrand(t, f, b)
}

func TestApplyLoginBranding_FailsWhenActivationDoesNotStick(t *testing.T) {
	f := newFakeLabelZitadel(t)
	f.ignoreActivate = true
	_, err := applyLoginBranding(context.Background(), f.client(), testBrand())
	if err == nil || !strings.Contains(err.Error(), "after activation") {
		t.Fatalf("apply = %v, want an after-activation failure", err)
	}
}

func TestApplyLoginBranding_FailsWhenAMarkDoesNotStick(t *testing.T) {
	f := newFakeLabelZitadel(t)
	b := testBrand()
	maps.Copy(f.preview.fields, b.policy)
	maps.Copy(f.active.fields, b.policy)
	f.ignoreActivate = true
	_, err := applyLoginBranding(context.Background(), f.client(), b)
	if err == nil || !strings.Contains(err.Error(), "does not serve the declared mark") {
		t.Fatalf("apply = %v, want a mark failure", err)
	}
}

func TestApplyLoginBranding_ZitadelErrors(t *testing.T) {
	for _, path := range []string{
		"/admin/v1/policies/label",
		"/admin/v1/policies/label/_activate",
		"/admin/v1/policies/label/logo",
		"/assets/v1/instance/policy/label/icon",
	} {
		t.Run(path, func(t *testing.T) {
			f := newFakeLabelZitadel(t)
			f.fail = path
			if _, err := applyLoginBranding(context.Background(), f.client(), testBrand()); err == nil {
				t.Fatalf("apply with %s failing = nil error", path)
			}
		})
	}
}

// TestApplyLoginBranding_UnreadableMarkFails: a served mark that cannot be
// read is an error, not "stale", so the step does not rewrite blindly.
func TestApplyLoginBranding_UnreadableMarkFails(t *testing.T) {
	f := newFakeLabelZitadel(t)
	if _, err := applyLoginBranding(context.Background(), f.client(), testBrand()); err != nil {
		t.Fatal(err)
	}
	f.failAssets = true
	uploads := f.uploads
	if _, err := applyLoginBranding(context.Background(), f.client(), testBrand()); err == nil {
		t.Fatal("apply with unreadable marks = nil error")
	}
	if f.uploads != uploads {
		t.Errorf("an unreadable mark was rewritten blindly (%d uploads)", f.uploads-uploads)
	}
}

func TestPolicyMatches(t *testing.T) {
	want := map[string]any{"primaryColor": "#34A000", "hideLoginNameSuffix": true}
	cases := []struct {
		active map[string]any
		match  bool
	}{
		{map[string]any{"primaryColor": "#34a000", "hideLoginNameSuffix": true, "extra": 1}, true},
		{map[string]any{"primaryColor": "#34a000", "hideLoginNameSuffix": false}, false},
		{map[string]any{"primaryColor": "#000000", "hideLoginNameSuffix": true}, false},
		{map[string]any{"hideLoginNameSuffix": true}, false},
	}
	for i, c := range cases {
		if got := policyMatches(c.active, want); got != c.match {
			t.Errorf("case %d: policyMatches = %v, want %v", i, got, c.match)
		}
	}
}

// ---------------------------------------------------------------- reconcile

func brandingConfigMap(data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "zitadel-login-branding", Namespace: defaultChildNamespace},
		Data:       data,
	}
}

func validBrandData() map[string]string {
	return map[string]string{
		brandPolicyKey: `{"primaryColor":"#346000","hideLoginNameSuffix":true}`,
		brandLogoKey:   "<svg>logo</svg>",
		brandIconKey:   "<svg>icon</svg>",
	}
}

func brandingReconciler(t *testing.T, zitadelURL string, withPAT bool, cms ...*corev1.ConfigMap) *PlatformBootstrapReconciler {
	t.Helper()
	s := mustScheme(t)
	b := fake.NewClientBuilder().WithScheme(s)
	if withPAT {
		b = b.WithObjects(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "iam-admin-pat", Namespace: defaultChildNamespace},
			Data:       map[string][]byte{"pat": []byte("test-pat")},
		})
	}
	for _, cm := range cms {
		b = b.WithObjects(cm)
	}
	return &PlatformBootstrapReconciler{
		Client:   b.Build(),
		Scheme:   s,
		Recorder: record.NewFakeRecorder(8),
		ZitadelFactory: func(_, pat string) zitadel.Client {
			return zitadel.New(zitadelURL, pat, "")
		},
	}
}

func brandedPlatformBootstrap() *gibsonv1alpha1.PlatformBootstrap {
	pb := newTestPlatformBootstrap(true)
	pb.Spec.Zitadel.LoginBranding = &gibsonv1alpha1.LoginBrandingSpec{ConfigMap: "zitadel-login-branding"}
	return pb
}

func brandingCond(t *testing.T, pb *gibsonv1alpha1.PlatformBootstrap) *metav1.Condition {
	t.Helper()
	c := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionLoginBrandingReady)
	if c == nil {
		t.Fatal("LoginBrandingReady was not set")
	}
	return c
}

func TestReconcileLoginBranding_AppliesTheDeclaredBrand(t *testing.T) {
	f := newFakeLabelZitadel(t)
	r := brandingReconciler(t, f.srv.URL, true, brandingConfigMap(validBrandData()))
	pb := brandedPlatformBootstrap()
	r.reconcileLoginBranding(context.Background(), pb, logr.Discard())
	if c := brandingCond(t, pb); c.Status != metav1.ConditionTrue || c.Reason != "BrandApplied" {
		t.Fatalf("LoginBrandingReady = %+v, want True/BrandApplied", c)
	}
	if !policyMatches(f.active.fields, map[string]any{"primaryColor": "#346000"}) {
		t.Errorf("active fields = %v", f.active.fields)
	}
	if ev := <-r.Recorder.(*record.FakeRecorder).Events; !strings.Contains(ev, "LoginBrandingApplied") {
		t.Errorf("event = %q, want LoginBrandingApplied", ev)
	}
}

func TestReconcileLoginBranding_NotDeclared(t *testing.T) {
	r := brandingReconciler(t, "http://unused.invalid", true)
	pb := newTestPlatformBootstrap(true)
	r.reconcileLoginBranding(context.Background(), pb, logr.Discard())
	if c := brandingCond(t, pb); c.Status != metav1.ConditionTrue || c.Reason != "NotDeclared" {
		t.Fatalf("LoginBrandingReady = %+v, want True/NotDeclared", c)
	}
}

func TestReconcileLoginBranding_WaitsAndFails(t *testing.T) {
	f := newFakeLabelZitadel(t)
	badJSON := validBrandData()
	badJSON[brandPolicyKey] = "not json"
	noLogo := validBrandData()
	delete(noLogo, brandLogoKey)
	cases := []struct {
		name   string
		cms    []*corev1.ConfigMap
		pat    bool
		fail   string
		reason string
	}{
		{"no ConfigMap", nil, true, "", "WaitingForBrand"},
		{"policy is not JSON", []*corev1.ConfigMap{brandingConfigMap(badJSON)}, true, "", "WaitingForBrand"},
		{"no logo", []*corev1.ConfigMap{brandingConfigMap(noLogo)}, true, "", "WaitingForBrand"},
		{"no admin token", []*corev1.ConfigMap{brandingConfigMap(validBrandData())}, false, "", "WaitingForAdminToken"},
		{"Zitadel fails", []*corev1.ConfigMap{brandingConfigMap(validBrandData())}, true, "/admin/v1/policies/label", "ZitadelError"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.fail = tc.fail
			r := brandingReconciler(t, f.srv.URL, tc.pat, tc.cms...)
			pb := brandedPlatformBootstrap()
			r.reconcileLoginBranding(context.Background(), pb, logr.Discard())
			if c := brandingCond(t, pb); c.Status != metav1.ConditionFalse || c.Reason != tc.reason {
				t.Fatalf("LoginBrandingReady = %+v, want False/%s", c, tc.reason)
			}
		})
	}
}

func TestMapBrandingConfigMap(t *testing.T) {
	s := mustScheme(t)
	named := brandedPlatformBootstrap()
	named.Name = "named"
	other := newTestPlatformBootstrap(true)
	other.Name = "unbranded"
	elsewhere := brandedPlatformBootstrap()
	elsewhere.Name = "elsewhere"
	elsewhere.Spec.Zitadel.LoginBranding.Namespace = "branding"
	r := &PlatformBootstrapReconciler{Client: fake.NewClientBuilder().WithScheme(s).WithObjects(named, other, elsewhere).Build()}

	got := r.mapBrandingConfigMap(context.Background(), brandingConfigMap(nil))
	if len(got) != 1 || got[0].Name != "named" {
		t.Errorf("map(gibson/zitadel-login-branding) = %v, want [named]", got)
	}
	cm := brandingConfigMap(nil)
	cm.Namespace = "branding"
	if got := r.mapBrandingConfigMap(context.Background(), cm); len(got) != 1 || got[0].Name != "elsewhere" {
		t.Errorf("map(branding/zitadel-login-branding) = %v, want [elsewhere]", got)
	}
	cm = brandingConfigMap(nil)
	cm.Name = "unrelated"
	if got := r.mapBrandingConfigMap(context.Background(), cm); len(got) != 0 {
		t.Errorf("map(unrelated) = %v, want none", got)
	}
}
