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

// --- systemClient --------------------------------------------------------

// fakeSystemClient stands in for the Zitadel System API (gibson#794):
// validTokens are the tokens Zitadel accepts, minted counts each mint, and
// mintErr and validErr fail the calls.
type fakeSystemClient struct {
	validTokens map[string]bool
	minted      int
	mintErr     error
	validErr    error
	retired     []string // "<user>:<kept id>" of each RemoveOtherTokens call
	retireErr   error
}

func (f *fakeSystemClient) mintFor(userName string) (userID string, tok zitadel.PAT, err error) {
	if f.mintErr != nil {
		return "", zitadel.PAT{}, f.mintErr
	}
	f.minted++
	pat := zitadel.PAT{ID: fmt.Sprintf("pat-id-%d", f.minted), Token: fmt.Sprintf("pat-%d", f.minted)}
	if f.validTokens == nil {
		f.validTokens = map[string]bool{}
	}
	f.validTokens[pat.Token] = true
	return "user-" + userName, pat, nil
}

func (f *fakeSystemClient) MintAdminToken(_ context.Context, userName string, _ time.Time) (userID string, tok zitadel.PAT, err error) {
	return f.mintFor(userName)
}

func (f *fakeSystemClient) MintUserToken(_ context.Context, userName string, _ time.Time) (userID string, tok zitadel.PAT, err error) {
	return f.mintFor(userName)
}

func (f *fakeSystemClient) AdminTokenValid(_ context.Context, pat string) (bool, error) {
	if f.validErr != nil {
		return false, f.validErr
	}
	return f.validTokens[pat], nil
}

func (f *fakeSystemClient) TokenValid(ctx context.Context, pat string) (bool, error) {
	return f.AdminTokenValid(ctx, pat)
}

func (f *fakeSystemClient) RemoveOtherTokens(_ context.Context, userID, keepID string) (int, error) {
	if f.retireErr != nil {
		return 0, f.retireErr
	}
	f.retired = append(f.retired, userID+":"+keepID)
	return 1, nil
}

// capturedFactoryArgs records what the reconciler handed the client factory.
type capturedFactoryArgs struct {
	apiURL         string
	systemUserName string
	externalDomain string
	keyPath        string
}

// capturingFactory returns a SystemClientFactory that records its arguments
// in got and returns a fake client.
func capturingFactory(got *capturedFactoryArgs) SystemClientFactory {
	return func(apiURL, systemUserName, externalDomain, keyPath string) (zitadel.SystemClient, error) {
		*got = capturedFactoryArgs{apiURL, systemUserName, externalDomain, keyPath}
		return &fakeSystemClient{}, nil
	}
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

// TestSystemClient_UnsetAPIURL_DialsInCluster is the backwards-compatibility
// case: a PlatformBootstrap written before the apiURL field existed dials the
// in-cluster Service, never the public issuer, and claims the public host
// from ZITADEL_EXTERNAL_DOMAIN.
func TestSystemClient_UnsetAPIURL_DialsInCluster(t *testing.T) {
	t.Setenv("ZITADEL_URL", "")
	t.Setenv("ZITADEL_EXTERNAL_DOMAIN", "app.example.com")

	var got capturedFactoryArgs
	r := &PlatformBootstrapReconciler{SystemClientFactory: capturingFactory(&got)}

	// No apiURL, no externalDomain: the shape an already-installed cluster has.
	if _, err := r.systemClient(newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{
		KeyPath: writeTestSystemMount(t, "gibson-system-bot"),
	}, "")); err != nil {
		t.Fatalf("systemClient: %v", err)
	}
	if got.apiURL != testInClusterAddr {
		t.Errorf("apiURL = %q, want in-cluster %q", got.apiURL, testInClusterAddr)
	}
	if got.apiURL == testIssuer {
		t.Errorf("apiURL still points at the public issuer %q", testIssuer)
	}
	if got.externalDomain != "app.example.com" {
		t.Errorf("claimed host = %q, want %q", got.externalDomain, "app.example.com")
	}
	if got.systemUserName != "gibson-system-bot" {
		t.Errorf("systemUserName = %q, want gibson-system-bot from the mount", got.systemUserName)
	}
}

// TestSystemClient_ExplicitAPIURL proves the CRD seam is honoured and that an
// explicit externalDomain wins.
func TestSystemClient_ExplicitAPIURL(t *testing.T) {
	t.Setenv("ZITADEL_URL", "http://env.svc:8080")

	var got capturedFactoryArgs
	r := &PlatformBootstrapReconciler{SystemClientFactory: capturingFactory(&got)}
	pb := newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{
		APIURL:  "http://zitadel.gibson.svc:8080",
		KeyPath: writeTestSystemMount(t, "gibson-system-bot-b"),
	}, testExternalDomain)

	if _, err := r.systemClient(pb); err != nil {
		t.Fatalf("systemClient: %v", err)
	}
	if got.apiURL != "http://zitadel.gibson.svc:8080" {
		t.Errorf("apiURL = %q, want the spec value", got.apiURL)
	}
	if got.externalDomain != testExternalDomain {
		t.Errorf("claimed host = %q, want %q", got.externalDomain, testExternalDomain)
	}
	if got.systemUserName != "gibson-system-bot-b" {
		t.Errorf("systemUserName = %q, want gibson-system-bot-b from the mount", got.systemUserName)
	}
}

// TestSystemClient_EnvFallback covers a chart that sets only the operator-Pod
// env var and no CRD field.
func TestSystemClient_EnvFallback(t *testing.T) {
	t.Setenv("ZITADEL_URL", "http://gibson-zitadel.gibson.svc:8080")

	var got capturedFactoryArgs
	r := &PlatformBootstrapReconciler{SystemClientFactory: capturingFactory(&got)}
	if _, err := r.systemClient(newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{
		KeyPath: writeTestSystemMount(t, "gibson-system-bot"),
	}, testExternalDomain)); err != nil {
		t.Fatalf("systemClient: %v", err)
	}
	if got.apiURL != "http://gibson-zitadel.gibson.svc:8080" {
		t.Errorf("apiURL = %q, want the env value", got.apiURL)
	}
}

// TestSystemClient_ClaimedHostReachesTheWire wires the REAL
// zitadel.NewSystemClient through the reconciler against a local server that
// stands in for the in-cluster Zitadel Service. The connection goes to the
// in-cluster address, and the instance header carries the public domain.
func TestSystemClient_ClaimedHostReachesTheWire(t *testing.T) {
	t.Setenv("ZITADEL_URL", "")

	var gotInstance string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotInstance = r.Header.Get(zitadelconn.InstanceHostHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"org":{"id":"org-1"}}`))
	}))
	t.Cleanup(srv.Close)

	r := &PlatformBootstrapReconciler{SystemClientFactory: DefaultSystemClientFactory}
	// srv.URL stands in for the cluster Service address: a host that is NOT
	// the public domain.
	pb := newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{
		APIURL:  srv.URL,
		KeyPath: writeTestSystemMount(t, "gibson-system-bot"),
	}, testExternalDomain)

	sys, err := r.systemClient(pb)
	if err != nil {
		t.Fatalf("systemClient: %v", err)
	}
	if _, err := sys.AdminTokenValid(context.Background(), "a-token"); err != nil {
		t.Fatalf("AdminTokenValid: %v", err)
	}
	if gotInstance != testExternalDomain {
		t.Errorf("instance header = %q, want %q", gotInstance, testExternalDomain)
	}
	if strings.Contains(srv.URL, testExternalDomain) {
		t.Fatalf("test setup broken: dial target %q is the public domain", srv.URL)
	}
}

// writeTestRSAKey writes a throwaway RSA private key PEM into t's temp dir
// and returns its path.
// writeTestSystemMount writes a key and the file "user" beside it, as the
// chart mount holds them, and returns the key path.
func writeTestSystemMount(t *testing.T, user string) string {
	t.Helper()
	path := writeTestRSAKey(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), zitadel.SystemUserFile), []byte(user+"\n"), 0o600); err != nil {
		t.Fatalf("write user: %v", err)
	}
	return path
}

// TestSystemClient_MountNamesNoUser: a key with no user beside it is an error,
// not a default user.
func TestSystemClient_MountNamesNoUser(t *testing.T) {
	var got capturedFactoryArgs
	r := &PlatformBootstrapReconciler{SystemClientFactory: capturingFactory(&got)}
	pb := newTestBootstrap(&gibsonv1alpha1.SystemClientSpec{KeyPath: writeTestRSAKey(t)}, testExternalDomain)
	_, err := r.systemClient(pb)
	if err == nil {
		t.Fatal("systemClient with no user file: want an error, got nil")
	}
	if got.systemUserName != "" {
		t.Errorf("the factory ran with user %q", got.systemUserName)
	}
}

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
