// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// caPEM is a valid CA bundle of one certificate.
func caPEM(t *testing.T) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertDER(t)})
}

func caInstance(namespace string) *connectorv1alpha1.ConnectorInstance {
	ci := hostedInstance("github-fixloop", namespace)
	ci.UID = types.UID("uid-github-fixloop")
	ci.Spec.CABundleSecret = "github-fixloop-ca-mock"
	return ci
}

func caSecret(t *testing.T, ci *connectorv1alpha1.ConnectorInstance, namespace string, owned bool) *corev1.Secret {
	t.Helper()
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: caSecretName(ci.Name), Namespace: namespace},
		Data:       map[string][]byte{caBundleKey: caPEM(t)},
	}
	if owned {
		sec.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: connectorv1alpha1.GroupVersion.String(), Kind: "ConnectorInstance", Name: ci.Name, UID: ci.UID,
		}}
	}
	return sec
}

func podSpecOf(t *testing.T, th *unstructured.Unstructured) map[string]interface{} {
	t.Helper()
	ps, found, _ := unstructured.NestedMap(th.Object, "spec", "podTemplateSpec", "spec")
	if !found {
		t.Fatal("the MCPServer has no podTemplateSpec")
	}
	return ps
}

func envOf(th *unstructured.Unstructured) map[string]string {
	raw, _, _ := unstructured.NestedSlice(th.Object, "spec", "env")
	out := map[string]string{}
	for _, e := range raw {
		m := e.(map[string]interface{})
		out[m["name"].(string)] = m["value"].(string)
	}
	return out
}

// The pod of a connector with a bundle mounts the CA Secret of that connector
// and sets SSL_CERT_FILE. The value of the catalog entry does not win.
func TestCABundle_MountsAndSetsTheTrustEnv(t *testing.T) {
	r := newReconciler(t)
	ci := caInstance("tenant-acme")
	ci.Spec.Env = map[string]string{"GITHUB_ENVIRONMENT": "production", sslCertFileEnv: "/other/file"}
	th, err := r.desiredToolHive(ci)
	if err != nil {
		t.Fatal(err)
	}
	if got := envOf(th); got[sslCertFileEnv] != caBundleFile || got["GITHUB_ENVIRONMENT"] != "production" {
		t.Errorf("env = %v, want SSL_CERT_FILE=%s and the plain variable", got, caBundleFile)
	}
	ps := podSpecOf(t, th)
	vols, _, _ := unstructured.NestedSlice(ps, "volumes")
	if len(vols) != 1 {
		t.Fatalf("volumes = %v", vols)
	}
	if name, _, _ := unstructured.NestedString(vols[0].(map[string]interface{}), "secret", "secretName"); name != "github-fixloop-connector-ca" {
		t.Errorf("the volume mounts Secret %q", name)
	}
	cs, _, _ := unstructured.NestedSlice(ps, "containers")
	mounts, _, _ := unstructured.NestedSlice(cs[0].(map[string]interface{}), "volumeMounts")
	if len(mounts) != 1 || mounts[0].(map[string]interface{})["mountPath"] != caBundleMountDir ||
		mounts[0].(map[string]interface{})["readOnly"] != true {
		t.Errorf("mounts = %v", mounts)
	}
}

// A connector without the field is unchanged: no volume, no mount, no env.
func TestCABundle_NoFieldLeavesThePodUnchanged(t *testing.T) {
	r := newReconciler(t)
	ci := hostedInstance("plain", "tenant-acme")
	ci.Spec.Env = map[string]string{"A": "b"}
	th, err := r.desiredToolHive(ci)
	if err != nil {
		t.Fatal(err)
	}
	ps := podSpecOf(t, th)
	if _, found := ps["volumes"]; found {
		t.Error("the pod has a volume")
	}
	cs, _, _ := unstructured.NestedSlice(ps, "containers")
	if _, found := cs[0].(map[string]interface{})["volumeMounts"]; found {
		t.Error("the container has a mount")
	}
	if got := envOf(th); len(got) != 1 || got["A"] != "b" {
		t.Errorf("env = %v, want only A", got)
	}
}

func reconcileOnce(t *testing.T, r *ConnectorInstanceReconciler, ci *connectorv1alpha1.ConnectorInstance) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ci)})
}

func mcpServerExists(t *testing.T, r *ConnectorInstanceReconciler, ci *connectorv1alpha1.ConnectorInstance) bool {
	t.Helper()
	err := r.Get(context.Background(), client.ObjectKeyFromObject(ci), newToolHive(kindMCPServer))
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

// The pod waits for the Secret. A Secret of the same name in the namespace of
// another tenant is never mounted.
func TestCABundle_RefusesASecretOfAnotherNamespace(t *testing.T) {
	ci := caInstance("tenant-acme")
	other := caSecret(t, ci, "tenant-rival", true)
	r := newReconciler(t, ci, other)

	res, err := reconcileOnce(t, r, ci)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.RequeueAfter == 0 {
		t.Error("the connector did not wait for its own Secret")
	}
	if mcpServerExists(t, r, ci) {
		t.Error("the MCPServer was made without the CA Secret of this tenant")
	}
	// The check itself refuses a Secret of another namespace.
	if cerr := checkCABundleSecret(other, ci); !errors.Is(cerr, ErrCABundle) || !strings.Contains(cerr.Error(), "tenant-rival") {
		t.Errorf("checkCABundleSecret = %v, want ErrCABundle that names the namespace", cerr)
	}
}

// A Secret with the right name that the ConnectorInstance does not own is
// refused, and the connector fails.
func TestCABundle_RefusesASecretThatTheInstanceDoesNotOwn(t *testing.T) {
	ci := caInstance("tenant-acme")
	r := newReconciler(t, ci, caSecret(t, ci, "tenant-acme", false))
	if _, err := reconcileOnce(t, r, ci); !errors.Is(err, ErrCABundle) {
		t.Fatalf("reconcile err = %v, want ErrCABundle", err)
	}
	if mcpServerExists(t, r, ci) {
		t.Error("the MCPServer was made with a Secret that the instance does not own")
	}
}

// An owned Secret in the namespace of the connector is mounted.
func TestCABundle_OwnedSecretIsMounted(t *testing.T) {
	ci := caInstance("tenant-acme")
	r := newReconciler(t, ci, caSecret(t, ci, "tenant-acme", true))
	if _, err := reconcileOnce(t, r, ci); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	th := newToolHive(kindMCPServer)
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(ci), th); err != nil {
		t.Fatalf("no MCPServer: %v", err)
	}
	if envOf(th)[sslCertFileEnv] != caBundleFile {
		t.Errorf("env = %v", envOf(th))
	}
}

// Another connector of the same tenant, with no field, gets no mount even when
// a CA Secret of its neighbor exists.
func TestCABundle_OnlyTheNamedConnectorMounts(t *testing.T) {
	withCA := caInstance("tenant-acme")
	plain := hostedInstance("prometheus-health", "tenant-acme")
	r := newReconciler(t, withCA, plain, caSecret(t, withCA, "tenant-acme", true))
	if _, err := reconcileOnce(t, r, plain); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	th := newToolHive(kindMCPServer)
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(plain), th); err != nil {
		t.Fatal(err)
	}
	if _, found := podSpecOf(t, th)["volumes"]; found {
		t.Error("a connector with no bundle got a volume")
	}
	if _, set := envOf(th)[sslCertFileEnv]; set {
		t.Error("a connector with no bundle got SSL_CERT_FILE")
	}
}

// Only a Hosted connector takes a bundle.
func TestCABundle_RemoteIsRefused(t *testing.T) {
	ci := remoteInstance("gitlab", "tenant-acme")
	ci.Spec.CABundleSecret = "gitlab-ca-x"
	r := newReconciler(t, ci)
	if _, err := reconcileOnce(t, r, ci); !errors.Is(err, ErrCABundle) {
		t.Fatalf("reconcile err = %v, want ErrCABundle", err)
	}
}

// The PEM check accepts CA certificates and nothing else.
func TestCheckCAPEM(t *testing.T) {
	good := caPEM(t)
	key := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("k")})
	cases := map[string]struct {
		data []byte
		ok   bool
	}{
		"one certificate":  {good, true},
		"two certificates": {append(append([]byte{}, good...), good...), true},
		"a private key":    {append(append([]byte{}, good...), key...), false},
		"not PEM":          {[]byte("hello"), false},
		"empty":            {nil, false},
		"bad certificate":  {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}), false},
	}
	for name, c := range cases {
		err := checkCAPEM(c.data)
		if c.ok != (err == nil) {
			t.Errorf("%s: err = %v, want ok=%v", name, err, c.ok)
		}
	}
}

func caWish(tenant string) *daemonoperatorv1.DesiredConnector {
	return &daemonoperatorv1.DesiredConnector{ //nolint:gosec // G101: the name of a secret, no value
		TenantId: tenant, ConnectorId: "github-fixloop", Shape: "Hosted", Image: "registry.example/x@sha256:ab",
		Transport: "streamable-http", Auth: "none", CaBundleSecret: "github-fixloop-ca-mock",
	}
}

// The loop asks the daemon for the bundle of the tenant, writes it to its own
// Secret in the namespace of that tenant, and keeps it out of the credential
// Secret.
func TestCABundle_LoopWritesTheSecretInTheTenantNamespace(t *testing.T) {
	d := &fakeDesiredDaemon{
		desired: []*daemonoperatorv1.DesiredConnector{caWish("acme")},
		cred: &daemonoperatorv1.GetConnectorCredentialResponse{Data: map[string][]byte{
			caBundleKey: caPEM(t), "API_VALUE": []byte("v"),
		}},
	}
	r, c := desiredLoop(t, d)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	refs := d.credReqs[0].GetCredentials()
	if d.credReqs[0].GetTenantId() != "acme" || len(refs) != 1 ||
		refs[0].GetKey() != "github-fixloop-ca-mock" || refs[0].GetTargetEnv() != caBundleKey {
		t.Fatalf("request = %v", d.credReqs[0])
	}
	sec := &corev1.Secret{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "tenant-acme", Name: "github-fixloop-connector-ca"}, sec); err != nil {
		t.Fatalf("no CA Secret: %v", err)
	}
	if len(sec.OwnerReferences) != 1 || sec.OwnerReferences[0].Kind != "ConnectorInstance" {
		t.Errorf("owner = %v", sec.OwnerReferences)
	}
	cred, ok := credSecret(t, c, "tenant-acme", "github-fixloop")
	if !ok {
		t.Fatal("no credential Secret")
	}
	if _, leaked := cred.Data[caBundleKey]; leaked {
		t.Error("the bundle is in the credential Secret")
	}
}

// A bundle with a private key is refused, and no Secret is written.
func TestCABundle_LoopRefusesAKeyInTheBundle(t *testing.T) {
	bad := append(caPEM(t), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("k")})...)
	d := &fakeDesiredDaemon{
		desired: []*daemonoperatorv1.DesiredConnector{caWish("acme")},
		cred:    &daemonoperatorv1.GetConnectorCredentialResponse{Data: map[string][]byte{caBundleKey: bad}},
	}
	r, c := desiredLoop(t, d)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	sec := &corev1.Secret{}
	err := c.Get(context.Background(), client.ObjectKey{Namespace: "tenant-acme", Name: "github-fixloop-connector-ca"}, sec)
	if !apierrors.IsNotFound(err) {
		t.Errorf("a Secret was written for a bundle with a key (err = %v)", err)
	}
	if got := d.lastReport(t); !strings.Contains(got.GetLastError(), "PRIVATE KEY") {
		t.Errorf("report = %v", got)
	}
}

// The bundle of one tenant never goes to the namespace of another tenant.
func TestCABundle_SyncRefusesAnotherTenantNamespace(t *testing.T) {
	d := &fakeDesiredDaemon{cred: &daemonoperatorv1.GetConnectorCredentialResponse{
		Data: map[string][]byte{caBundleKey: caPEM(t)},
	}}
	r, c := desiredLoop(t, d)
	ci := caInstance("tenant-rival")
	err := r.syncCredential(context.Background(), "acme", ci)
	if !errors.Is(err, ErrCABundle) {
		t.Fatalf("err = %v, want ErrCABundle", err)
	}
	if len(d.credReqs) != 0 {
		t.Error("the loop asked the daemon for the bundle of tenant acme for the namespace of tenant rival")
	}
	sec := &corev1.Secret{}
	if gerr := c.Get(context.Background(), client.ObjectKey{Namespace: "tenant-rival", Name: "github-fixloop-connector-ca"}, sec); !apierrors.IsNotFound(gerr) {
		t.Errorf("a Secret was written to the namespace of the other tenant (err = %v)", gerr)
	}
}

func podAnnotation(t *testing.T, th *unstructured.Unstructured) string {
	t.Helper()
	v, _, _ := unstructured.NestedString(th.Object, "spec", "podTemplateSpec", "metadata", "annotations", caBundleHashAnnotation)
	return v
}

// A new bundle changes the hash on the pod template, so the pod rolls and reads
// the new file. The same bundle gives the same hash, and a connector with no
// bundle has no annotation.
func TestCABundle_AnewBundleRollsThePod(t *testing.T) {
	ci := caInstance("tenant-acme")
	sec := caSecret(t, ci, "tenant-acme", true)
	r := newReconciler(t, ci, sec)
	get := func() string {
		if _, err := reconcileOnce(t, r, ci); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		th := newToolHive(kindMCPServer)
		if err := r.Get(context.Background(), client.ObjectKeyFromObject(ci), th); err != nil {
			t.Fatal(err)
		}
		return podAnnotation(t, th)
	}
	first := get()
	if len(first) != 64 {
		t.Fatalf("hash = %q, want a sha256", first)
	}
	if again := get(); again != first {
		t.Errorf("the same bundle changed the hash: %q vs %q", first, again)
	}
	var live corev1.Secret
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(sec), &live); err != nil {
		t.Fatal(err)
	}
	other := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertDER(t)})
	live.Data[caBundleKey] = other
	if err := r.Update(context.Background(), &live); err != nil {
		t.Fatal(err)
	}
	if rolled := get(); rolled == first {
		t.Error("a new bundle did not change the hash on the pod template")
	}

	plain := hostedInstance("plain", "tenant-acme")
	r2 := newReconciler(t, plain)
	if _, err := reconcileOnce(t, r2, plain); err != nil {
		t.Fatal(err)
	}
	th := newToolHive(kindMCPServer)
	if err := r2.Get(context.Background(), client.ObjectKeyFromObject(plain), th); err != nil {
		t.Fatal(err)
	}
	if podAnnotation(t, th) != "" {
		t.Error("a connector with no bundle has the annotation")
	}
}

// A Secret with the name of the CA Secret that the instance does not own is not
// taken over: it keeps its data and its owners, and the loop reports the error.
func TestCABundle_LoopDoesNotTakeOverASecret(t *testing.T) {
	foreign := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "github-fixloop-connector-ca", Namespace: "tenant-acme",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "someone", UID: "u-1"}},
		},
		Data: map[string][]byte{"ca.crt": []byte("theirs")},
	}
	d := &fakeDesiredDaemon{
		desired: []*daemonoperatorv1.DesiredConnector{caWish("acme")},
		cred:    &daemonoperatorv1.GetConnectorCredentialResponse{Data: map[string][]byte{caBundleKey: caPEM(t)}},
	}
	r, c := desiredLoop(t, d, foreign)
	if err := r.converge(context.Background()); err != nil {
		t.Fatalf("converge: %v", err)
	}
	var got corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(foreign), &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Data["ca.crt"]) != "theirs" || got.OwnerReferences[0].Name != "someone" {
		t.Errorf("the Secret was taken over: %v %v", got.Data, got.OwnerReferences)
	}
	if rep := d.lastReport(t); !strings.Contains(rep.GetLastError(), "does not own") {
		t.Errorf("report = %v", rep)
	}
}

// The old CA Secret goes when the tenant clears the bundle.
func TestCABundle_ClearingTheVariableDeletesTheSecret(t *testing.T) {
	d := &fakeDesiredDaemon{
		desired: []*daemonoperatorv1.DesiredConnector{caWish("acme")},
		cred:    &daemonoperatorv1.GetConnectorCredentialResponse{Data: map[string][]byte{caBundleKey: caPEM(t)}},
	}
	r, c := desiredLoop(t, d)
	if err := r.converge(context.Background()); err != nil {
		t.Fatal(err)
	}
	key := client.ObjectKey{Namespace: "tenant-acme", Name: "github-fixloop-connector-ca"}
	var sec corev1.Secret
	if err := c.Get(context.Background(), key, &sec); err != nil {
		t.Fatalf("no CA Secret: %v", err)
	}
	d.desired[0].CaBundleSecret = ""
	if err := r.converge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), key, &sec); !apierrors.IsNotFound(err) {
		t.Errorf("the CA Secret is still there (err = %v)", err)
	}
}
