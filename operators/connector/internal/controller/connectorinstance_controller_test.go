// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// testScheme knows the connector types, the core/networking types, and the two
// unstructured ToolHive kinds, so the fake client can create, get and update
// every object the reconciler touches.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("clientgoscheme: %v", err)
	}
	if err := connectorv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("connector scheme: %v", err)
	}
	for _, gvk := range []schema.GroupVersionKind{
		schema.FromAPIVersionAndKind(toolhiveAPIVersion, kindMCPServer),
		schema.FromAPIVersionAndKind(toolhiveAPIVersion, kindMCPServer+"List"),
		schema.FromAPIVersionAndKind(toolhiveAPIVersion, kindMCPRemoteProxy),
		schema.FromAPIVersionAndKind(toolhiveAPIVersion, kindMCPRemoteProxy+"List"),
	} {
		s.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
	}
	return s
}

// fakeRevoker records the finalizer's revoke calls and answers as told.
type fakeRevoker struct {
	calls []string // "<tenant>/<connector>"
	err   error
}

func (f *fakeRevoker) Revoke(_ context.Context, tenantID, connector string) error {
	f.calls = append(f.calls, tenantID+"/"+connector)
	return f.err
}

func newReconciler(t *testing.T, seed ...client.Object) *ConnectorInstanceReconciler {
	t.Helper()
	s := testScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&connectorv1alpha1.ConnectorInstance{}).
		WithObjects(seed...).
		Build()
	return &ConnectorInstanceReconciler{Client: cl, Scheme: s, Revoker: &fakeRevoker{}}
}

func hostedInstance(name, namespace string) *connectorv1alpha1.ConnectorInstance {
	return &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: connectorv1alpha1.ConnectorInstanceSpec{
			Connector: name,
			Shape:     connectorv1alpha1.ConnectorShapeHosted,
			Image:     "ghcr.io/example/mcp:latest",
			Runtime:   connectorv1alpha1.ConnectorRuntimePod,
			Auth:      connectorv1alpha1.ConnectorAuthNone,
		},
	}
}

// remoteInstance is a Remote (MCPRemoteProxy) connector fixture — the shape the
// gitlab connector uses. Its ToolHive terminal phase is "Ready", not "Running".
func remoteInstance(name, namespace string) *connectorv1alpha1.ConnectorInstance {
	return &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: connectorv1alpha1.ConnectorInstanceSpec{
			Connector: name,
			Shape:     connectorv1alpha1.ConnectorShapeRemote,
			Endpoint:  "https://gitlab.com/api/v4/mcp",
			Auth:      connectorv1alpha1.ConnectorAuthOAuth,
		},
	}
}

// TestDesiredToolHive_Hosted maps a Hosted connector to an MCPServer with the
// builtin network profile and the connector's image.
func TestDesiredToolHive_Hosted(t *testing.T) {
	r := &ConnectorInstanceReconciler{}
	ci := hostedInstance("osv", "tenant-acme")

	th, err := r.desiredToolHive(ci)
	if err != nil {
		t.Fatalf("desiredToolHive: %v", err)
	}
	if th.GetKind() != kindMCPServer {
		t.Errorf("kind = %q, want %q", th.GetKind(), kindMCPServer)
	}
	img, _, _ := unstructured.NestedString(th.Object, "spec", "image")
	if img != "ghcr.io/example/mcp:latest" {
		t.Errorf("image = %q", img)
	}
	profType, _, _ := unstructured.NestedString(th.Object, "spec", "permissionProfile", "type")
	if profType != "builtin" {
		t.Errorf("permissionProfile.type = %q, want builtin", profType)
	}
}

// TestDesiredToolHive_HostedNeedsImage rejects a Hosted connector with no image.
func TestDesiredToolHive_HostedNeedsImage(t *testing.T) {
	r := &ConnectorInstanceReconciler{}
	ci := hostedInstance("osv", "tenant-acme")
	ci.Spec.Image = ""

	if _, err := r.desiredToolHive(ci); err == nil {
		t.Fatal("expected an error for a Hosted connector with no image")
	}
}

// TestDesiredToolHive_Remote maps a Remote connector to an MCPRemoteProxy with
// the vendor endpoint, kubernetes OIDC, and a forwarded credential header when
// the connector authenticates.
func TestDesiredToolHive_Remote(t *testing.T) {
	r := &ConnectorInstanceReconciler{}
	ci := &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "gitlab", Namespace: "tenant-acme"},
		Spec: connectorv1alpha1.ConnectorInstanceSpec{
			Connector: "gitlab",
			Shape:     connectorv1alpha1.ConnectorShapeRemote,
			Endpoint:  "https://gitlab.com/api/v4/mcp",
			Auth:      connectorv1alpha1.ConnectorAuthOAuth,
		},
	}

	th, err := r.desiredToolHive(ci)
	if err != nil {
		t.Fatalf("desiredToolHive: %v", err)
	}
	if th.GetKind() != kindMCPRemoteProxy {
		t.Errorf("kind = %q, want %q", th.GetKind(), kindMCPRemoteProxy)
	}
	remote, _, _ := unstructured.NestedString(th.Object, "spec", "remoteURL")
	if remote != "https://gitlab.com/api/v4/mcp" {
		t.Errorf("remoteURL = %q", remote)
	}
	oidc, _, _ := unstructured.NestedString(th.Object, "spec", "oidcConfig", "type")
	if oidc != "kubernetes" {
		t.Errorf("oidcConfig.type = %q, want kubernetes", oidc)
	}
	if _, found, _ := unstructured.NestedSlice(th.Object, "spec", "headerForward", "addHeadersFromSecret"); !found {
		t.Error("an authenticated Remote connector must forward a credential header")
	}
}

// TestDesiredToolHive_RemoteNeedsEndpoint rejects a Remote connector with no
// endpoint, and an unknown shape is rejected too.
func TestDesiredToolHive_RemoteNeedsEndpoint(t *testing.T) {
	r := &ConnectorInstanceReconciler{}
	ci := &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "gitlab", Namespace: "tenant-acme"},
		Spec:       connectorv1alpha1.ConnectorInstanceSpec{Shape: connectorv1alpha1.ConnectorShapeRemote},
	}
	if _, err := r.desiredToolHive(ci); err == nil {
		t.Fatal("expected an error for a Remote connector with no endpoint")
	}

	ci.Spec.Shape = "Bogus"
	if _, err := r.desiredToolHive(ci); err == nil {
		t.Fatal("expected an error for an unknown shape")
	}
}

// TestReconcile_HostedCreatesResources drives a full reconcile of a Hosted
// connector: the finalizer is added, the NetworkPolicy and the ToolHive
// MCPServer are created, and the instance requeues while ToolHive is not yet
// Running.
func TestReconcile_HostedCreatesResources(t *testing.T) {
	r := newReconciler(t, hostedInstance("osv", "tenant-acme"))
	ctx := context.Background()
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "osv"}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The owned NetworkPolicy exists.
	var np networkingv1.NetworkPolicy
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-acme", Name: "connector-osv"}, &np); err != nil {
		t.Fatalf("networkpolicy not created: %v", err)
	}

	// The ToolHive MCPServer exists.
	th := newToolHive(kindMCPServer)
	if err := r.Get(ctx, key, th); err != nil {
		t.Fatalf("toolhive not created: %v", err)
	}

	// The finalizer is set.
	var ci connectorv1alpha1.ConnectorInstance
	if err := r.Get(ctx, key, &ci); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if len(ci.Finalizers) == 0 {
		t.Error("finalizer must be set")
	}
}

// TestReconcile_NotFoundIsNoOp returns cleanly when the instance is gone.
func TestReconcile_NotFoundIsNoOp(t *testing.T) {
	r := newReconciler(t)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: "ghost"},
	})
	if err != nil {
		t.Fatalf("reconcile of a missing instance should be a no-op, got: %v", err)
	}
}

// TestReconcile_DeletionRunsFinalizer removes the finalizer on a deleted
// instance so Kubernetes can garbage-collect it.
func TestReconcile_DeletionRunsFinalizer(t *testing.T) {
	ci := hostedInstance("osv", "tenant-acme")
	now := metav1.Now()
	ci.DeletionTimestamp = &now
	ci.Finalizers = []string{finalizer}
	r := newReconciler(t, ci)
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "osv"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile deletion: %v", err)
	}
	assertFinalizerReleased(t, r, key)
	// An auth-none connector has no grant, so nothing is revoked.
	if calls := r.Revoker.(*fakeRevoker).calls; len(calls) != 0 {
		t.Errorf("auth none must not revoke; got %v", calls)
	}
}

// assertFinalizerReleased checks the finalizer is gone, so the object is
// collectable (the fake client removes it once the last finalizer clears).
func assertFinalizerReleased(t *testing.T, r *ConnectorInstanceReconciler, key types.NamespacedName) {
	t.Helper()
	var got connectorv1alpha1.ConnectorInstance
	if err := r.Get(context.Background(), key, &got); err == nil {
		if len(got.Finalizers) != 0 {
			t.Errorf("finalizer still present: %v", got.Finalizers)
		}
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected get error: %v", err)
	}
}

// deletingInstance marks ci as deleting at deletedAt with the finalizer set,
// the state the API server hands the reconciler after a delete.
func deletingInstance(ci *connectorv1alpha1.ConnectorInstance, deletedAt time.Time) *connectorv1alpha1.ConnectorInstance {
	ts := metav1.NewTime(deletedAt)
	ci.DeletionTimestamp = &ts
	ci.Finalizers = []string{finalizer}
	return ci
}

// TestReconcile_DeletionRevokesTheGrant is the ADR-0015 §5 regression: deleting
// an oauth connector revokes its grant through the daemon with the tenant
// recovered from the namespace, then releases the finalizer.
func TestReconcile_DeletionRevokesTheGrant(t *testing.T) {
	deletedAt := time.Unix(1_700_000_000, 0).UTC()
	ci := deletingInstance(remoteInstance("gitlab", "tenant-primary"), deletedAt)
	r := newReconciler(t, ci)
	r.Now = func() time.Time { return deletedAt.Add(time.Second) }
	key := types.NamespacedName{Namespace: "tenant-primary", Name: "gitlab"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile deletion: %v", err)
	}
	if calls := r.Revoker.(*fakeRevoker).calls; len(calls) != 1 || calls[0] != "primary/gitlab" {
		t.Errorf("revoke calls = %v, want [primary/gitlab]", calls)
	}
	assertFinalizerReleased(t, r, key)
}

// A failing revoke inside the deadline keeps the finalizer, records the
// failure on the status, and returns the error so the controller requeues
// with backoff — the grant is not silently abandoned.
func TestReconcile_DeletionRetriesAFailingRevoke(t *testing.T) {
	deletedAt := time.Unix(1_700_000_000, 0).UTC()
	ci := deletingInstance(secretInstance("github", "tenant-primary"), deletedAt)
	r := newReconciler(t, ci)
	r.Revoker = &fakeRevoker{err: errors.New("daemon unavailable")}
	r.Now = func() time.Time { return deletedAt.Add(time.Minute) }
	key := types.NamespacedName{Namespace: "tenant-primary", Name: "github"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("a failing revoke inside the deadline must return an error to requeue")
	}
	var got connectorv1alpha1.ConnectorInstance
	if err := r.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("the instance must still exist: %v", err)
	}
	if len(got.Finalizers) != 1 {
		t.Errorf("finalizer must be kept while retrying; got %v", got.Finalizers)
	}
	if got.Status.Phase != connectorv1alpha1.ConnectorInstancePhaseDeprovisioning || got.Status.LastError == "" {
		t.Errorf("phase = %q lastError = %q, want Deprovisioning with the revoke error", got.Status.Phase, got.Status.LastError)
	}
}

// Past the deadline the finalizer releases with a logged warning rather than
// wedging the delete behind a daemon that stays down.
func TestReconcile_DeletionReleasesAfterTheRevokeDeadline(t *testing.T) {
	deletedAt := time.Unix(1_700_000_000, 0).UTC()
	ci := deletingInstance(secretInstance("github", "tenant-primary"), deletedAt)
	r := newReconciler(t, ci)
	r.Revoker = &fakeRevoker{err: errors.New("daemon unavailable")}
	r.Now = func() time.Time { return deletedAt.Add(revokeDeadline + time.Second) }
	key := types.NamespacedName{Namespace: "tenant-primary", Name: "github"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("past the deadline the finalizer must release: %v", err)
	}
	assertFinalizerReleased(t, r, key)
}

// A ConnectorInstance outside a tenant namespace has no tenant store to
// revoke in; the revoke is an error, retried until the deadline like any
// other, and the revoker is never called with a made-up tenant.
func TestReconcile_DeletionOutsideTenantNamespaceNeverInventsATenant(t *testing.T) {
	deletedAt := time.Unix(1_700_000_000, 0).UTC()
	ci := deletingInstance(remoteInstance("gitlab", "default"), deletedAt)
	r := newReconciler(t, ci)
	r.Now = func() time.Time { return deletedAt.Add(time.Second) }
	key := types.NamespacedName{Namespace: "default", Name: "gitlab"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("a non-tenant namespace must surface an error")
	}
	if calls := r.Revoker.(*fakeRevoker).calls; len(calls) != 0 {
		t.Errorf("revoker must not be called; got %v", calls)
	}
}

// TestReconcileEgressProfile covers the no-op path (no egress allow-list) and
// the create path (a profile ConfigMap is written), then the update path.
func TestReconcileEgressProfile(t *testing.T) {
	ctx := context.Background()

	// No-op: no egress allow-list means no ConfigMap.
	r := newReconciler(t)
	ci := hostedInstance("osv", "tenant-acme")
	if err := r.reconcileEgressProfile(ctx, ci); err != nil {
		t.Fatalf("reconcileEgressProfile no-op: %v", err)
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-acme", Name: egressProfileName(ci)}, &cm); !apierrors.IsNotFound(err) {
		t.Fatalf("expected no ConfigMap, got err=%v", err)
	}

	// Create: an egress allow-list writes the profile ConfigMap.
	ci.Spec.EgressAllow = []string{"api.osv.dev:443"}
	if err := r.reconcileEgressProfile(ctx, ci); err != nil {
		t.Fatalf("reconcileEgressProfile create: %v", err)
	}
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-acme", Name: egressProfileName(ci)}, &cm); err != nil {
		t.Fatalf("egress ConfigMap not created: %v", err)
	}
	if cm.Data[egressProfileKey] == "" {
		t.Error("profile payload must be written")
	}

	// Update: a second reconcile with a changed allow-list updates in place.
	ci.Spec.EgressAllow = []string{"api.osv.dev:443", "extra.example.com:443"}
	if err := r.reconcileEgressProfile(ctx, ci); err != nil {
		t.Fatalf("reconcileEgressProfile update: %v", err)
	}
}

// TestReconcileNetworkPolicy renders and applies the owned NetworkPolicy, then
// updates it on a second pass.
func TestReconcileNetworkPolicy(t *testing.T) {
	ctx := context.Background()
	r := newReconciler(t)
	ci := hostedInstance("osv", "tenant-acme")

	if err := r.reconcileNetworkPolicy(ctx, ci); err != nil {
		t.Fatalf("reconcileNetworkPolicy create: %v", err)
	}
	var np networkingv1.NetworkPolicy
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-acme", Name: "connector-osv"}, &np); err != nil {
		t.Fatalf("networkpolicy not created: %v", err)
	}
	if len(np.Spec.Egress) == 0 || len(np.Spec.Ingress) == 0 {
		t.Error("networkpolicy must carry ingress and egress rules")
	}

	// A second pass updates the live policy.
	if err := r.reconcileNetworkPolicy(ctx, ci); err != nil {
		t.Fatalf("reconcileNetworkPolicy update: %v", err)
	}
}

// TestHelpers covers the small pure helpers.
func TestHelpers(t *testing.T) {
	if got := credentialSecretName("gitlab"); got != "gitlab-connector-cred" {
		t.Errorf("credentialSecretName = %q", got)
	}
	ci := hostedInstance("osv", "tenant-acme")
	if hasEgressProfile(ci) {
		t.Error("no egress allow-list means hasEgressProfile is false")
	}
	np := desiredNetworkPolicy(ci)
	if np.Name != "connector-osv" {
		t.Errorf("networkpolicy name = %q", np.Name)
	}
}

// assertServingPhaseBecomesReady drives the two-pass reconcile: the first pass
// creates the owned ToolHive resource, then the test sets its status.phase to
// the given serving phase, and the second pass must flip the ConnectorInstance
// to Ready and publish its proxy URL. Shared by the Hosted (MCPServer/"Running")
// and Remote (MCPRemoteProxy/"Ready") cases, which differ only in kind + phase.
func assertServingPhaseBecomesReady(
	t *testing.T,
	ci *connectorv1alpha1.ConnectorInstance,
	toolHiveKind, servingPhase string,
) {
	t.Helper()
	r := newReconciler(t, ci)
	ctx := context.Background()
	key := types.NamespacedName{Namespace: ci.Namespace, Name: ci.Name}

	// First pass creates the ToolHive resource; it has no phase yet.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	// Simulate ToolHive bringing the proxy up to its serving phase.
	th := newToolHive(toolHiveKind)
	if err := r.Get(ctx, key, th); err != nil {
		t.Fatalf("get toolhive: %v", err)
	}
	_ = unstructured.SetNestedField(th.Object, servingPhase, "status", "phase")
	if err := r.Update(ctx, th); err != nil {
		t.Fatalf("update toolhive status: %v", err)
	}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	var got connectorv1alpha1.ConnectorInstance
	if err := r.Get(ctx, key, &got); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if got.Status.Phase != connectorv1alpha1.ConnectorInstancePhaseReady {
		t.Errorf("phase = %q, want Ready", got.Status.Phase)
	}
	if got.Status.ProxyURL == "" {
		t.Error("a Ready connector must publish its proxy URL")
	}
}

// TestReconcile_RunningBecomesReady flips a Hosted connector to Ready once its
// owned MCPServer reports the "Running" serving phase.
func TestReconcile_RunningBecomesReady(t *testing.T) {
	assertServingPhaseBecomesReady(
		t, hostedInstance("osv", "tenant-acme"), kindMCPServer, "Running")
}

// TestReconcile_RemoteReadyBecomesReady flips a Remote connector to Ready once
// its owned MCPRemoteProxy reports the "Ready" serving phase — the terminal
// phase an MCPRemoteProxy uses (an MCPServer uses "Running"). Without the
// kind-aware serving-phase check, a Remote connector is stranded in
// Provisioning forever.
func TestReconcile_RemoteReadyBecomesReady(t *testing.T) {
	assertServingPhaseBecomesReady(
		t, remoteInstance("gitlab", "tenant-primary"), kindMCPRemoteProxy, "Ready")
}

// secretInstance is a Remote connector with a customer-supplied static
// credential (auth secret) — the shape the github connector uses. The daemon
// writes its <name>-connector-cred Secret from the tenant store (ADR-0015); the
// operator only references it.
func secretInstance(name, namespace string) *connectorv1alpha1.ConnectorInstance {
	return &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: connectorv1alpha1.ConnectorInstanceSpec{
			Connector: name,
			Shape:     connectorv1alpha1.ConnectorShapeRemote,
			Endpoint:  "https://api.githubcopilot.com/mcp/",
			Auth:      connectorv1alpha1.ConnectorAuthSecret,
		},
	}
}

// TestReconcile_SecretAuthBecomesReady is the ADR-0015 regression for an
// auth-secret connector: the operator reconciles it without any ExternalSecret
// step, wires the daemon-written credential Secret into the proxy's
// Authorization header, and flips it to Ready once the proxy serves. Before
// ADR-0015 this path emitted an ExternalSecret that fought the daemon for the
// same Secret name and pulled a key nothing ever wrote.
func TestReconcile_SecretAuthBecomesReady(t *testing.T) {
	ci := secretInstance("github", "tenant-primary")
	assertServingPhaseBecomesReady(t, ci, kindMCPRemoteProxy, "Ready")

	r := newReconciler(t, secretInstance("github", "tenant-primary"))
	ctx := context.Background()
	key := types.NamespacedName{Namespace: "tenant-primary", Name: "github"}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	th := newToolHive(kindMCPRemoteProxy)
	if err := r.Get(ctx, key, th); err != nil {
		t.Fatalf("get proxy: %v", err)
	}
	headers, _, _ := unstructured.NestedSlice(th.Object, "spec", "headerForward", "addHeadersFromSecret")
	if len(headers) != 1 {
		t.Fatalf("addHeadersFromSecret = %v, want exactly the Authorization header", headers)
	}
	ref, _, _ := unstructured.NestedString(headers[0].(map[string]interface{}), "valueSecretRef", "name")
	if ref != "github-connector-cred" {
		t.Errorf("proxy reads Secret %q, want github-connector-cred (the daemon's connectorCredSecretName)", ref)
	}
}

// TestReconcile_InvalidSpecFails records a Failed phase and returns the error
// when the spec cannot be mapped to a ToolHive resource.
func TestReconcile_InvalidSpecFails(t *testing.T) {
	bad := hostedInstance("osv", "tenant-acme")
	bad.Spec.Image = "" // a Hosted connector with no image is invalid
	r := newReconciler(t, bad)
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "osv"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("an invalid spec must return an error")
	}
	var ci connectorv1alpha1.ConnectorInstance
	if err := r.Get(context.Background(), key, &ci); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if ci.Status.Phase != connectorv1alpha1.ConnectorInstancePhaseFailed {
		t.Errorf("phase = %q, want Failed", ci.Status.Phase)
	}
	if ci.Status.LastError == "" {
		t.Error("a failed reconcile must record the reason")
	}
}

// failingReconciler builds a reconciler whose client fails every Create with a
// generic error, so the create-error branches of the reconcile helpers and the
// reconcile fail() path are exercised.
func failingReconciler(t *testing.T, seed ...client.Object) *ConnectorInstanceReconciler {
	t.Helper()
	s := testScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&connectorv1alpha1.ConnectorInstance{}).
		WithObjects(seed...).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
				return errReconcileBoom
			},
		}).
		Build()
	return &ConnectorInstanceReconciler{Client: cl, Scheme: s}
}

var errReconcileBoom = reconcileBoom("kube write refused")

type reconcileBoom string

func (e reconcileBoom) Error() string { return string(e) }

// TestReconcileNetworkPolicy_CreateError wraps a client write failure.
func TestReconcileNetworkPolicy_CreateError(t *testing.T) {
	r := failingReconciler(t)
	if err := r.reconcileNetworkPolicy(context.Background(), hostedInstance("osv", "tenant-acme")); err == nil {
		t.Error("a failed NetworkPolicy create must surface an error")
	}
}

// TestReconcileEgressProfile_CreateError wraps a client write failure.
func TestReconcileEgressProfile_CreateError(t *testing.T) {
	ci := hostedInstance("osv", "tenant-acme")
	ci.Spec.EgressAllow = []string{"api.osv.dev:443"}
	r := failingReconciler(t)
	if err := r.reconcileEgressProfile(context.Background(), ci); err == nil {
		t.Error("a failed egress ConfigMap create must surface an error")
	}
}

// TestReconcile_NetworkPolicyErrorIsFailed records a Failed phase when the very
// first owned resource cannot be written.
func TestReconcile_NetworkPolicyErrorIsFailed(t *testing.T) {
	// Seed the instance already carrying the finalizer so the reconcile reaches
	// the NetworkPolicy step instead of returning after the finalizer update.
	ci := hostedInstance("osv", "tenant-acme")
	ci.Finalizers = []string{finalizer}
	r := failingReconciler(t, ci)
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "osv"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("a failed owned-resource write must surface an error")
	}
	var got connectorv1alpha1.ConnectorInstance
	if err := r.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if got.Status.Phase != connectorv1alpha1.ConnectorInstancePhaseFailed {
		t.Errorf("phase = %q, want Failed", got.Status.Phase)
	}
}

// failCreateOfKind builds a reconciler whose client fails Create only for the
// named kind, so one reconcile step fails while the earlier steps succeed.
func failCreateOfKind(t *testing.T, kind string, seed ...client.Object) *ConnectorInstanceReconciler {
	t.Helper()
	s := testScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&connectorv1alpha1.ConnectorInstance{}).
		WithObjects(seed...).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				// Unstructured objects carry their Kind; typed objects (ConfigMap,
				// NetworkPolicy) leave GetObjectKind empty, so match those by type.
				matches := obj.GetObjectKind().GroupVersionKind().Kind == kind
				if _, ok := obj.(*corev1.ConfigMap); ok && kind == "ConfigMap" {
					matches = true
				}
				if matches {
					return errReconcileBoom
				}
				return c.Create(ctx, obj, opts...)
			},
		}).
		Build()
	return &ConnectorInstanceReconciler{Client: cl, Scheme: s}
}

// TestReconcile_EgressErrorIsFailed fails the egress-profile step.
func TestReconcile_EgressErrorIsFailed(t *testing.T) {
	ci := hostedInstance("osv", "tenant-acme")
	ci.Finalizers = []string{finalizer}
	ci.Spec.EgressAllow = []string{"api.osv.dev:443"}
	r := failCreateOfKind(t, "ConfigMap", ci)
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "osv"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("a failed egress step must return an error")
	}
	assertFailed(t, r, key)
}

// TestReconcile_ApplyToolHiveErrorIsFailed fails the ToolHive apply step.
func TestReconcile_ApplyToolHiveErrorIsFailed(t *testing.T) {
	ci := hostedInstance("osv", "tenant-acme")
	ci.Finalizers = []string{finalizer}
	r := failCreateOfKind(t, kindMCPServer, ci)
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "osv"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("a failed ToolHive apply must return an error")
	}
	assertFailed(t, r, key)
}

func assertFailed(t *testing.T, r *ConnectorInstanceReconciler, key types.NamespacedName) {
	t.Helper()
	var got connectorv1alpha1.ConnectorInstance
	if err := r.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if got.Status.Phase != connectorv1alpha1.ConnectorInstancePhaseFailed {
		t.Errorf("phase = %q, want Failed", got.Status.Phase)
	}
}

// failGetReconciler fails every Get after the instance is loaded, so the
// non-NotFound Get-error branch of each reconcile helper is exercised.
func failGetReconciler(t *testing.T) *ConnectorInstanceReconciler {
	t.Helper()
	s := testScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&connectorv1alpha1.ConnectorInstance{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return errReconcileBoom
			},
		}).
		Build()
	return &ConnectorInstanceReconciler{Client: cl, Scheme: s}
}

// TestReconcileHelpers_GetErrorsAreWrapped checks that a non-NotFound read
// failure surfaces from each owned-resource reconcile helper.
func TestReconcileHelpers_GetErrorsAreWrapped(t *testing.T) {
	ctx := context.Background()

	ci := hostedInstance("osv", "tenant-acme")
	ci.Spec.EgressAllow = []string{"api.osv.dev:443"}

	r := failGetReconciler(t)
	if err := r.reconcileNetworkPolicy(ctx, ci); err == nil {
		t.Error("a failed NetworkPolicy read must surface an error")
	}
	if err := r.reconcileEgressProfile(ctx, ci); err == nil {
		t.Error("a failed egress read must surface an error")
	}
}

// TestSetupWithManager wires the reconciler into a manager built over a dummy
// rest.Config. The manager is constructed lazily (no API-server round trip), so
// this exercises the controller-registration wiring without a live cluster.
func TestSetupWithManager(t *testing.T) {
	mgr, err := manager.New(&rest.Config{Host: "https://127.0.0.1:6443"}, manager.Options{
		Scheme:  testScheme(t),
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	if err != nil {
		t.Fatalf("manager.New: %v", err)
	}
	r := &ConnectorInstanceReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}
}

// A deleting CR that no longer carries the finalizer is nothing to do, and a
// reconciler with no revoker wired cannot revoke — that is an error, retried
// like any other, never a silent release.
func TestReconcile_DeletionWithoutFinalizerOrRevoker(t *testing.T) {
	deletedAt := time.Unix(1_700_000_000, 0).UTC()
	bare := remoteInstance("gitlab", "tenant-primary")
	ts := metav1.NewTime(deletedAt)
	bare.DeletionTimestamp = &ts
	bare.Finalizers = []string{"other.example.com/hold"}
	r := newReconciler(t, bare)
	key := types.NamespacedName{Namespace: "tenant-primary", Name: "gitlab"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("no finalizer of ours means nothing to do: %v", err)
	}
	if calls := r.Revoker.(*fakeRevoker).calls; len(calls) != 0 {
		t.Errorf("revoker must not be called; got %v", calls)
	}

	r2 := newReconciler(t, deletingInstance(remoteInstance("gitlab", "tenant-primary"), deletedAt))
	r2.Revoker = nil
	r2.Now = func() time.Time { return deletedAt.Add(time.Second) }
	if _, err := r2.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("no revoker wired must surface an error")
	}
}

// The grant key is Spec.Connector; a CR that left it empty falls back to its
// name, the same rule the daemon's catalog source applies. The default clock
// (no Now injected) keeps a fresh delete inside the deadline.
func TestReconcile_DeletionFallsBackToNameAndDefaultClock(t *testing.T) {
	ci := deletingInstance(remoteInstance("gitlab", "tenant-primary"), time.Now())
	ci.Spec.Connector = ""
	r := newReconciler(t, ci)
	key := types.NamespacedName{Namespace: "tenant-primary", Name: "gitlab"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile deletion: %v", err)
	}
	if calls := r.Revoker.(*fakeRevoker).calls; len(calls) != 1 || calls[0] != "primary/gitlab" {
		t.Errorf("revoke calls = %v, want [primary/gitlab] from the CR name", calls)
	}

	r2 := newReconciler(t, deletingInstance(remoteInstance("gitlab", "tenant-primary"), time.Now()))
	r2.Revoker = &fakeRevoker{err: errors.New("daemon unavailable")}
	if _, err := r2.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err == nil {
		t.Fatal("a fresh delete with a failing revoke must retry (default clock is inside the deadline)")
	}
}

// A failed finalizer removal surfaces so the controller retries the update.
func TestReconcile_DeletionRemoveFinalizerErrorIsWrapped(t *testing.T) {
	ci := deletingInstance(hostedInstance("osv", "tenant-acme"), time.Now())
	s := testScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&connectorv1alpha1.ConnectorInstance{}).
		WithObjects(ci).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.UpdateOption) error {
				if _, ok := obj.(*connectorv1alpha1.ConnectorInstance); ok {
					return errors.New("conflict")
				}
				return nil
			},
		}).
		Build()
	r := &ConnectorInstanceReconciler{Client: cl, Scheme: s, Revoker: &fakeRevoker{}}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: "osv"}})
	if err == nil || !strings.Contains(err.Error(), "remove finalizer") {
		t.Fatalf("err = %v, want a wrapped remove-finalizer error", err)
	}
}
