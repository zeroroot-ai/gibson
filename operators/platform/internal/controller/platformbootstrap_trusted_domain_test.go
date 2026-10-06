// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

const (
	testIssuer         = "https://app.example.com"
	testInClusterAddr  = "http://gibson-zitadel.gibson.svc.cluster.local:8080"
	testClusterDomain  = "gibson-zitadel.gibson.svc.cluster.local"
	testExternalDomain = "app.example.com"
)

// --- systemAPIBaseURL ------------------------------------------------------

func TestSystemAPIBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		specURL string
		env     string
		want    string
	}{
		{
			name:    "spec apiURL wins",
			specURL: "http://zitadel.other.svc:8080",
			env:     "http://ignored.svc:8080",
			want:    "http://zitadel.other.svc:8080",
		},
		{
			name: "env fallback when spec empty",
			env:  "http://gibson-zitadel.gibson.svc:8080",
			want: "http://gibson-zitadel.gibson.svc:8080",
		},
		{
			name: "derived in-cluster default when spec and env empty",
			want: testInClusterAddr,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ZITADEL_URL", tc.env)
			got := systemAPIBaseURL(tc.specURL, testClusterDomain)
			if got != tc.want {
				t.Fatalf("systemAPIBaseURL = %q, want %q", got, tc.want)
			}
			// The whole point of the seam: the System API base URL is never
			// the internet-facing issuer origin.
			if strings.Contains(got, "app.example.com") {
				t.Fatalf("systemAPIBaseURL = %q leaks the public issuer host", got)
			}
		})
	}
}

// --- systemAPIClaimedHost --------------------------------------------------

func TestSystemAPIClaimedHost(t *testing.T) {
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", "env.example.com")
	if got := systemAPIClaimedHost(testExternalDomain); got != testExternalDomain {
		t.Errorf("systemAPIClaimedHost(spec) = %q, want the spec value %q", got, testExternalDomain)
	}
	if got := systemAPIClaimedHost(""); got != "env.example.com" {
		t.Errorf("systemAPIClaimedHost(empty spec) = %q, want ZITADEL_EXTERNAL_DOMAIN", got)
	}
}

// --- reconcileTrustedDomain ------------------------------------------------

// fakeSystemClient records the calls reconcileTrustedDomain makes.
type fakeSystemClient struct {
	existing []string
	added    []string
	addErr   error
	listErr  error

	// The admin token half (gibson#794): validTokens are the tokens Zitadel
	// accepts, minted counts each mint, and mintErr and validErr fail the calls.
	validTokens map[string]bool
	minted      int
	mintErr     error
	validErr    error
}

func (f *fakeSystemClient) MintAdminToken(_ context.Context, userName string, _ time.Time) (userID, pat string, err error) {
	if f.mintErr != nil {
		return "", "", f.mintErr
	}
	f.minted++
	pat = fmt.Sprintf("pat-%d", f.minted)
	if f.validTokens == nil {
		f.validTokens = map[string]bool{}
	}
	f.validTokens[pat] = true
	return "user-" + userName, pat, nil
}

func (f *fakeSystemClient) AdminTokenValid(_ context.Context, pat string) (bool, error) {
	if f.validErr != nil {
		return false, f.validErr
	}
	return f.validTokens[pat], nil
}

func (f *fakeSystemClient) ListInstanceDomains(context.Context) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.existing, nil
}

func (f *fakeSystemClient) AddInstanceDomain(_ context.Context, d string) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.added = append(f.added, d)
	return nil
}

// capturedFactoryArgs records what the reconciler handed the client factory.
type capturedFactoryArgs struct {
	apiURL         string
	systemUserName string
	externalDomain string
	keyPath        string
}

func newTestBootstrap(sc *gibsonv1alpha1.SystemClientSpec, externalDomain string) *gibsonv1alpha1.PlatformBootstrap {
	return &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "gibson"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			Zitadel: gibsonv1alpha1.ZitadelSpec{
				ExternalDomain: externalDomain,
				SystemClient:   sc,
			},
		},
	}
}

// TestReconcileTrustedDomain_UnsetAPIURL_DialsInCluster is the
// backwards-compatibility case: an existing PlatformBootstrap written before
// the apiURL field existed must still reconcile, and must now dial the
// in-cluster Service rather than the public issuer.
func TestReconcileTrustedDomain_UnsetAPIURL_DialsInCluster(t *testing.T) {
	t.Setenv("ZITADEL_URL", "")
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", "app.example.com")

	var got capturedFactoryArgs
	fake := &fakeSystemClient{}

	r := &PlatformBootstrapReconciler{
		Audit: (&audittest.Sink{}).Emitter(t),
		SystemClientFactory: func(apiURL, systemUserName, externalDomain, keyPath string) (zitadel.SystemClient, error) {
			got = capturedFactoryArgs{apiURL, systemUserName, externalDomain, keyPath}
			return fake, nil
		},
	}

	// No apiURL, no externalDomain — the shape an already-installed cluster has.
	pb := newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{}, "")

	res, err := r.reconcileTrustedDomain(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileTrustedDomain: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("expected no requeue, got %+v", res)
	}

	if got.apiURL != testInClusterAddr {
		t.Errorf("apiURL = %q, want in-cluster %q", got.apiURL, testInClusterAddr)
	}
	if got.apiURL == testIssuer {
		t.Errorf("apiURL still points at the public issuer %q", testIssuer)
	}
	// The claimed host comes from ZITADEL_EXTERNAL_DOMAIN because the spec
	// leaves externalDomain unset. It is never derived from the issuer.
	if got.externalDomain != "app.example.com" {
		t.Errorf("claimed host = %q, want %q", got.externalDomain, "app.example.com")
	}
	if got.systemUserName != "gibson-system-bot" {
		t.Errorf("systemUserName = %q, want default gibson-system-bot", got.systemUserName)
	}

	// And it actually completed the registration.
	if len(fake.added) != 1 || fake.added[0] != testClusterDomain {
		t.Errorf("added domains = %v, want [%s]", fake.added, testClusterDomain)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionTrustedDomainReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("TrustedDomainReady = %+v, want True", cond)
	}
}

// TestReconcileTrustedDomain_ExplicitAPIURL proves the CRD seam is honoured
// and that an explicit externalDomain wins over the issuer-derived host.
func TestReconcileTrustedDomain_ExplicitAPIURL(t *testing.T) {
	t.Setenv("ZITADEL_URL", "http://env.svc:8080")

	var got capturedFactoryArgs
	r := &PlatformBootstrapReconciler{
		Audit: (&audittest.Sink{}).Emitter(t),
		SystemClientFactory: func(apiURL, systemUserName, externalDomain, keyPath string) (zitadel.SystemClient, error) {
			got = capturedFactoryArgs{apiURL, systemUserName, externalDomain, keyPath}
			return &fakeSystemClient{existing: []string{testClusterDomain}}, nil
		},
	}
	pb := newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{
		APIURL:         "http://zitadel.gibson.svc:8080",
		SystemUserName: "custom-bot",
	}, testExternalDomain)

	if _, err := r.reconcileTrustedDomain(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileTrustedDomain: %v", err)
	}

	if got.apiURL != "http://zitadel.gibson.svc:8080" {
		t.Errorf("apiURL = %q, want the spec value", got.apiURL)
	}
	if got.externalDomain != testExternalDomain {
		t.Errorf("forged Host = %q, want %q", got.externalDomain, testExternalDomain)
	}
	if got.systemUserName != "custom-bot" {
		t.Errorf("systemUserName = %q, want custom-bot", got.systemUserName)
	}
}

// TestReconcileTrustedDomain_EnvFallback covers a chart that sets only the
// operator-Pod env var and no CRD field.
func TestReconcileTrustedDomain_EnvFallback(t *testing.T) {
	t.Setenv("ZITADEL_URL", "http://gibson-zitadel.gibson.svc:8080")

	var got capturedFactoryArgs
	r := &PlatformBootstrapReconciler{
		Audit: (&audittest.Sink{}).Emitter(t),
		SystemClientFactory: func(apiURL, systemUserName, externalDomain, keyPath string) (zitadel.SystemClient, error) {
			got = capturedFactoryArgs{apiURL, systemUserName, externalDomain, keyPath}
			return &fakeSystemClient{}, nil
		},
	}
	pb := newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{}, testExternalDomain)

	if _, err := r.reconcileTrustedDomain(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileTrustedDomain: %v", err)
	}
	if got.apiURL != "http://gibson-zitadel.gibson.svc:8080" {
		t.Errorf("apiURL = %q, want the env value", got.apiURL)
	}
}

// TestReconcileTrustedDomain_NilSystemClient: with no system client the step
// cannot run, so its condition is False and never Ready (gibson#223).
func TestReconcileTrustedDomain_NilSystemClient(t *testing.T) {
	r := &PlatformBootstrapReconciler{
		Audit: (&audittest.Sink{}).Emitter(t),
		SystemClientFactory: func(string, string, string, string) (zitadel.SystemClient, error) {
			t.Fatal("factory must not be called when systemClient is nil")
			return nil, nil
		},
	}
	pb := newTestBootstrap(nil, "")

	if _, err := r.reconcileTrustedDomain(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileTrustedDomain: %v", err)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionTrustedDomainReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "SystemClientMissing" {
		t.Fatalf("condition = %+v, want False with reason SystemClientMissing", cond)
	}
}

// TestReconcileTrustedDomain_ClaimedHostReachesTheWire wires the REAL
// zitadel.NewSystemClient through the reconciler against a local server
// standing in for the in-cluster Zitadel Service. It proves end to end that
// the connection is made to the in-cluster address while the instance header
// carries the public domain — the property Zitadel's instance router
// depends on, and the one that makes the public /system/v1/ route deletable.
func TestReconcileTrustedDomain_ClaimedHostReachesTheWire(t *testing.T) {
	t.Setenv("ZITADEL_URL", "")

	var searchHost, domainsHost string
	mux := http.NewServeMux()
	mux.HandleFunc("/system/v1/instances/_search", func(w http.ResponseWriter, r *http.Request) {
		searchHost = r.Header.Get(zitadelconn.InstanceHostHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[{"id":"372802942115250284","domain":"app.example.com"}]}`))
	})
	mux.HandleFunc("/system/v1/instances/372802942115250284/domains/_search",
		func(w http.ResponseWriter, r *http.Request) {
			domainsHost = r.Header.Get(zitadelconn.InstanceHostHeader)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":[{"domain":"` + testClusterDomain + `"}]}`))
		})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	r := &PlatformBootstrapReconciler{Audit: (&audittest.Sink{}).Emitter(t), SystemClientFactory: DefaultSystemClientFactory}

	// srv.URL stands in for the cluster Service address: a host that is NOT
	// the public domain.
	pb := newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{
		APIURL:  srv.URL,
		KeyPath: writeTestRSAKey(t),
	}, testExternalDomain)

	if _, err := r.reconcileTrustedDomain(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileTrustedDomain: %v", err)
	}

	if searchHost != testExternalDomain || domainsHost != testExternalDomain {
		t.Errorf("instance header = (%q, %q), want %q on both requests",
			searchHost, domainsHost, testExternalDomain)
	}
	if strings.Contains(srv.URL, testExternalDomain) {
		t.Fatalf("test setup broken: dial target %q is the public domain", srv.URL)
	}

	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionTrustedDomainReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("TrustedDomainReady = %+v, want True", cond)
	}
}

// writeTestRSAKey writes a throwaway RSA private key PEM into t's temp dir
// and returns its path.
func writeTestRSAKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "system-key.pem")
	buf := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// TestZitadelConnectURLFromEnv: both names are required at startup, a ported
// claimed host is refused (ADR-0092), and the old variable name configures
// nothing.
func TestZitadelConnectURLFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	got, err := ZitadelConnectURLFromEnv(env(map[string]string{
		"ZITADEL_URL": "http://gibson-zitadel:8080", "ZITADEL_EXTERNAL_DOMAIN": testExternalDomain,
	}))
	if err != nil || got != "http://gibson-zitadel:8080" {
		t.Fatalf("ZitadelConnectURLFromEnv = %q, %v; want ZITADEL_URL", got, err)
	}
	for name, m := range map[string]map[string]string{
		"no ZITADEL_URL":             {"ZITADEL_EXTERNAL_DOMAIN": testExternalDomain},
		"no ZITADEL_EXTERNAL_DOMAIN": {"ZITADEL_URL": "http://gibson-zitadel:8080"},
		"a ported claimed host":      {"ZITADEL_URL": "http://gibson-zitadel:8080", "ZITADEL_EXTERNAL_DOMAIN": "app.example.com:30443"},
		"ZITADEL_INTERNAL_ADDRESS":   {"ZITADEL_INTERNAL_ADDRESS": "http://gibson-zitadel:8080", "ZITADEL_EXTERNAL_DOMAIN": testExternalDomain},
	} {
		if _, err := ZitadelConnectURLFromEnv(env(m)); err == nil {
			t.Errorf("%s: ZitadelConnectURLFromEnv = nil error, want refusal", name)
		}
	}
}

// TestDefaultZitadelClientFactory_ClaimsTheConfiguredHost: the production
// factory connects to the URL it is given and claims ZITADEL_EXTERNAL_DOMAIN
// with the instance header.
func TestDefaultZitadelClientFactory_ClaimsTheConfiguredHost(t *testing.T) {
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", testExternalDomain)
	var gotInstance string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotInstance = r.Header.Get(zitadelconn.InstanceHostHeader)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	ok, err := DefaultZitadelClientFactory(srv.URL, "pat").VerifyClientSecret(context.Background(), "client", "secret")
	if ok || err != nil {
		t.Fatalf("VerifyClientSecret = %v, %v; want (false, nil) for a 401", ok, err)
	}
	if gotInstance != testExternalDomain {
		t.Errorf("instance header = %q, want %q", gotInstance, testExternalDomain)
	}
}
