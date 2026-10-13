// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/zeroroot-ai/gibson/operators/internal/ciliumegress"
)

// testIssuerNS is the provider namespace that testProxyAuth.JWKSURL names.
const testIssuerNS = "spire-test"

// testCertDER is a self-signed CA certificate, the shape of a SPIRE root.
func testCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "spire-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return der
}

// trustBundle is the ConfigMap the SPIRE bundle publisher writes, with one
// X.509 root.
func trustBundle(t *testing.T, der []byte) *corev1.ConfigMap {
	t.Helper()
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: testIssuerNS, Name: "spire-bundle"},
		Data: map[string]string{"bundle.spiffe": `{"keys":[` +
			`{"use":"x509-svid","kty":"EC","x5c":["` + base64.StdEncoding.EncodeToString(der) + `"]},` +
			`{"use":"jwt-svid","kty":"EC","kid":"k1"}]}`},
	}
}

// pemOf is the PEM form of one certificate.
func pemOf(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// The JWKS URL names the provider namespace. A URL in another form is
// refused, so the operator never writes a rule for a guessed namespace.
func TestIssuerNamespace(t *testing.T) {
	for url, want := range map[string]string{
		"https://gibson-spiffe-oidc-discovery-provider.gibson.svc.cluster.local/keys": "gibson",
		"https://oidc.spire-system.svc/keys":                                          "spire-system",
		"https://oidc.example.org/keys":                                               "",
		"https://gibson-spiffe-oidc-discovery-provider/keys":                          "",
		"https://oidc.gibson/keys":                                                    "",
		"://bad":                                                                      "",
	} {
		got, err := ProxyAuth{JWKSURL: url}.IssuerNamespace()
		if want == "" {
			if err == nil {
				t.Errorf("%s: namespace %q, want an error", url, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%s: got (%q, %v), want %q", url, got, err, want)
		}
	}
}

// The issuer policy selects the proxy pod of the connector only. Its one
// rule reaches the provider pods of the provider namespace on 8443/TCP and
// nothing else. The test fails on a wider rule: a second rule, an entity, a
// namespace-wide selector, another label, or another port.
func TestDesiredProxyIssuerPolicy(t *testing.T) {
	u := desiredProxyIssuerPolicy(hostedInstance("gh", "tenant-acme"), "gibson")
	if u.GetName() != "connector-gh-proxy-issuer" || u.GetNamespace() != "tenant-acme" {
		t.Fatalf("name = %s/%s", u.GetNamespace(), u.GetName())
	}
	for name, c := range map[string]struct {
		labels map[string]string
		want   bool
	}{
		"the MCPServer proxy": {map[string]string{
			"app.kubernetes.io/name": "mcpserver", "toolhive-name": "gh",
		}, true},
		"the MCPRemoteProxy proxy": {map[string]string{
			"app.kubernetes.io/name": "mcpremoteproxy", "toolhive-name": "gh",
		}, true},
		"the MCP server pod": {map[string]string{"app": "gh", "toolhive-name": "gh"}, false},
		"the proxy of another connector": {map[string]string{
			"app.kubernetes.io/name": "mcpserver", "toolhive-name": "slack",
		}, false},
	} {
		if got := selects(t, u, c.labels); got != c.want {
			t.Errorf("%s: selected = %v, want %v", name, got, c.want)
		}
	}
	egress, _, _ := unstructured.NestedSlice(u.Object, "spec", "egress")
	want := []interface{}{map[string]interface{}{
		"toEndpoints": []interface{}{map[string]interface{}{
			"matchLabels": map[string]interface{}{
				"k8s:io.kubernetes.pod.namespace": "gibson",
				"app.kubernetes.io/name":          "spiffe-oidc-discovery-provider",
			},
		}},
		"toPorts": []interface{}{map[string]interface{}{
			"ports": []interface{}{map[string]interface{}{"port": "8443", "protocol": "TCP"}},
		}},
	}}
	if !reflect.DeepEqual(egress, want) {
		t.Errorf("egress = %v, want only the provider pods on 8443/TCP: %v", egress, want)
	}
}

// The reconcile writes the issuer policy for the provider namespace of the
// JWKS URL, and an update keeps it.
func TestReconcileProxyIssuerPolicy(t *testing.T) {
	ctx := context.Background()
	r := newReconciler(t)
	ci := hostedInstance("gh", "tenant-acme")
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "connector-gh-proxy-issuer"}
	for _, step := range []string{"create", "update"} {
		if err := r.reconcileProxyIssuerPolicy(ctx, ci); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		u := ciliumegress.NewPolicy()
		if err := r.Get(ctx, key, u); err != nil {
			t.Fatalf("%s: no policy: %v", step, err)
		}
		egress, _, _ := unstructured.NestedSlice(u.Object, "spec", "egress")
		if !reflect.DeepEqual(egress, desiredProxyIssuerPolicy(ci, testIssuerNS).Object["spec"].(map[string]interface{})["egress"]) {
			t.Errorf("%s: egress = %v", step, egress)
		}
		if len(u.GetOwnerReferences()) != 1 {
			t.Errorf("%s: owner references = %v", step, u.GetOwnerReferences())
		}
	}
}

// The copy of the trust bundle follows a change of the bundle: the change
// maps to a reconcile of the connector, and that reconcile writes the new
// root. A change of another ConfigMap maps to nothing.
func TestIssuerCAFollowsTheTrustBundle(t *testing.T) {
	ctx := context.Background()
	r := newReconciler(t)
	ci := hostedInstance("gh", "tenant-acme")
	if err := r.Create(ctx, ci); err != nil {
		t.Fatalf("create instance: %v", err)
	}
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "connector-gh-issuer-ca"}

	bundle := &corev1.ConfigMap{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: testIssuerNS, Name: "spire-bundle"}, bundle); err != nil {
		t.Fatalf("seeded bundle: %v", err)
	}
	if err := r.reconcileIssuerCA(ctx, ci); err != nil {
		t.Fatalf("first copy: %v", err)
	}
	first := &corev1.ConfigMap{}
	if err := r.Get(ctx, key, first); err != nil {
		t.Fatalf("no copy: %v", err)
	}
	if !strings.HasPrefix(first.Data["ca.crt"], "-----BEGIN CERTIFICATE-----") || len(first.GetOwnerReferences()) != 1 {
		t.Fatalf("copy = %v, owners %v", first.Data, first.GetOwnerReferences())
	}

	// SPIRE rotates its root.
	rotated := testCertDER(t)
	bundle.Data = trustBundle(t, rotated).Data
	if err := r.Update(ctx, bundle); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	reqs := r.trustBundleRequests(ctx, bundle)
	if len(reqs) != 1 || reqs[0].NamespacedName != client.ObjectKeyFromObject(ci) {
		t.Fatalf("requests = %v, want the one connector", reqs)
	}
	if err := r.reconcileIssuerCA(ctx, ci); err != nil {
		t.Fatalf("second copy: %v", err)
	}
	second := &corev1.ConfigMap{}
	if err := r.Get(ctx, key, second); err != nil {
		t.Fatalf("no copy: %v", err)
	}
	if second.Data["ca.crt"] != pemOf(rotated) {
		t.Errorf("copy after the rotation = %q, want the new root", second.Data["ca.crt"])
	}

	for name, other := range map[string]*corev1.ConfigMap{
		"same name, other namespace": {ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-acme", Name: "spire-bundle"}},
		"same namespace, other name": {ObjectMeta: metav1.ObjectMeta{Namespace: testIssuerNS, Name: "other"}},
	} {
		if reqs := r.trustBundleRequests(ctx, other); len(reqs) != 0 {
			t.Errorf("%s: requests = %v, want none", name, reqs)
		}
	}
}

// The full reconcile of a connector writes the issuer policy and the CA
// copy, and the proxy names that copy.
func TestReconcile_WritesTheIssuerTrustPath(t *testing.T) {
	ctx := context.Background()
	ci := hostedInstance("gh", "tenant-acme")
	r := newReconciler(t, ci)
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ci)}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-acme", Name: "connector-gh-proxy-issuer"},
		ciliumegress.NewPolicy()); err != nil {
		t.Errorf("no issuer policy: %v", err)
	}
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-acme", Name: "connector-gh-issuer-ca"},
		&corev1.ConfigMap{}); err != nil {
		t.Errorf("no CA copy: %v", err)
	}
}

// Each failure of the CA copy surfaces with its cause, and no copy is left
// with no root.
func TestReconcileIssuerCA_Errors(t *testing.T) {
	ctx := context.Background()
	ci := hostedInstance("gh", "tenant-acme")

	noBundle := newReconciler(t)
	if err := noBundle.Delete(ctx, trustBundle(t, nil)); err != nil {
		t.Fatalf("delete the seeded bundle: %v", err)
	}
	if err := noBundle.reconcileIssuerCA(ctx, ci); err == nil || !strings.Contains(err.Error(), "get the SPIRE trust bundle") {
		t.Errorf("no bundle: err = %v", err)
	}

	for name, c := range map[string]struct {
		data string
		want error
		text string
	}{
		"no root":  {`{"keys":[{"use":"jwt-svid","kid":"k1"}]}`, errEmptyTrustBundle, ""},
		"not json": {`{`, nil, "convert the SPIRE trust bundle"},
	} {
		r := newReconciler(t)
		bundle := trustBundle(t, nil)
		bundle.Data = map[string]string{"bundle.spiffe": c.data}
		if err := r.Update(ctx, bundle); err != nil {
			t.Fatalf("%s: update: %v", name, err)
		}
		err := r.reconcileIssuerCA(ctx, ci)
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
		if c.text != "" && (err == nil || !strings.Contains(err.Error(), c.text)) {
			t.Errorf("%s: err = %v, want %q", name, err, c.text)
		}
	}

	bad := newReconciler(t)
	bad.ProxyAuth.JWKSURL = "https://oidc.example.org/keys"
	if err := bad.reconcileIssuerCA(ctx, ci); err == nil {
		t.Error("a JWKS URL with no namespace was accepted")
	}
	if err := bad.reconcileProxyIssuerPolicy(ctx, ci); err == nil {
		t.Error("a JWKS URL with no namespace was accepted by the policy")
	}
	if reqs := bad.trustBundleRequests(ctx, trustBundle(t, nil)); len(reqs) != 0 {
		t.Errorf("requests with no namespace = %v", reqs)
	}
	if err := failGetReconciler(t).reconcileIssuerCA(ctx, ci); err == nil {
		t.Error("a failed read of the bundle was accepted")
	}
	if err := failGetReconciler(t).reconcileProxyIssuerPolicy(ctx, ci); err == nil ||
		!strings.Contains(err.Error(), "get proxy issuer policy") {
		t.Errorf("get: err = %v", err)
	}
}
