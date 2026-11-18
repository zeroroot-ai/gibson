// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/modelprovider"
)

// fakeModelCredentials is the daemon side of the credential read. A tenant secret
// that is not in data gives clients.ErrNotFound.
type fakeModelCredentials struct {
	data  map[string]map[string][]byte
	err   error
	calls []string
}

func (f *fakeModelCredentials) ModelProviderCredential(
	_ context.Context, tenantID, credentialSecret, providerType string,
) (map[string][]byte, error) {
	f.calls = append(f.calls, tenantID+"/"+credentialSecret+"/"+providerType)
	if f.err != nil {
		return nil, f.err
	}
	d, ok := f.data[credentialSecret]
	if !ok {
		return nil, fmt.Errorf("get: %w", clients.ErrNotFound)
	}
	return d, nil
}

func anthropicCredentials() *fakeModelCredentials {
	return &fakeModelCredentials{data: map[string]map[string][]byte{
		"anthropic-key": {"Authorization": []byte("sk-ant-1")},
	}}
}

func modelProviderTestRig(t *testing.T, mp *gibsonv1alpha1.ModelProvider, extra ...client.Object) (*ModelProviderReconciler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	objs := append([]client.Object{mp}, extra...)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&gibsonv1alpha1.ModelProvider{}).Build()
	r := &ModelProviderReconciler{
		Client: c, Scheme: scheme,
		Render: modelprovider.Config{
			Namespace: "gibson-gateway", GatewayName: "model-gateway",
			ExtAuthzName: "gibson-ext-authz", ExtAuthzNamespace: "gibson", ExtAuthzPort: 9001,
		},
		Credentials: &fakeModelCredentials{data: map[string]map[string][]byte{}},
	}
	return r, c
}

func newModelProvider() *gibsonv1alpha1.ModelProvider {
	return &gibsonv1alpha1.ModelProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "claude", Namespace: "tenant-acme", Generation: 1},
		Spec: gibsonv1alpha1.ModelProviderSpec{
			TenantID: "acme", Type: gibsonv1alpha1.ModelProviderAnthropic, CredentialSecret: "anthropic-key",
		},
	}
}

func reconcileTwice(t *testing.T, r *ModelProviderReconciler) ctrl.Result {
	t.Helper()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: "claude"}}
	var res ctrl.Result
	for range 2 {
		var err error
		if res, err = r.Reconcile(context.Background(), req); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}
	return res
}

func getObject(t *testing.T, c client.Client, kind, apiVersion, name string) (*unstructured.Unstructured, bool) {
	t.Helper()
	u := &unstructured.Unstructured{}
	u.SetAPIVersion(apiVersion)
	u.SetKind(kind)
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "gibson-gateway", Name: name}, u)
	return u, err == nil
}

func getModelProvider(t *testing.T, c client.Client) *gibsonv1alpha1.ModelProvider {
	t.Helper()
	var mp gibsonv1alpha1.ModelProvider
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "claude"}, &mp); err != nil {
		t.Fatal(err)
	}
	return &mp
}

// The controller renders the backend and the route into the namespace of the
// gateway, and it waits for the credential Secret.
func TestModelProvider_RendersAndWaitsForTheCredential(t *testing.T) {
	r, c := modelProviderTestRig(t, newModelProvider())
	res := reconcileTwice(t, r)

	if _, ok := getObject(t, c, "AgentgatewayBackend", "agentgateway.dev/v1alpha1", "mp-acme-claude"); !ok {
		t.Error("the backend was not created")
	}
	if _, ok := getObject(t, c, "HTTPRoute", "gateway.networking.k8s.io/v1", "mp-acme-claude"); !ok {
		t.Error("the route was not created")
	}
	got := getModelProvider(t, c)
	if got.Status.Phase != gibsonv1alpha1.ModelProviderPhaseWaitingForCredential || got.Status.Ready {
		t.Errorf("status = %+v, want WaitingForCredential", got.Status)
	}
	if got.Status.CredentialSecretName != "mp-acme-claude-credential" {
		t.Errorf("credential secret name = %q", got.Status.CredentialSecretName)
	}
	if res.RequeueAfter != modelProviderCredentialRetry {
		t.Errorf("requeue = %v, want %v", res.RequeueAfter, modelProviderCredentialRetry)
	}
}

// The controller writes the credential Secret from the content of the daemon,
// with the key name that the gateway reads, and the provider is Ready.
func TestModelProvider_WritesTheCredentialSecret(t *testing.T) {
	r, c := modelProviderTestRig(t, newModelProvider())
	src := anthropicCredentials()
	r.Credentials = src
	reconcileTwice(t, r)

	var secret corev1.Secret
	key := types.NamespacedName{Namespace: "gibson-gateway", Name: "mp-acme-claude-credential"}
	if err := c.Get(context.Background(), key, &secret); err != nil {
		t.Fatalf("the credential Secret was not written: %v", err)
	}
	if got := string(secret.Data["Authorization"]); got != "sk-ant-1" {
		t.Errorf("Authorization = %q", got)
	}
	if secret.Labels[modelprovider.LabelTenant] != "acme" || secret.Labels[modelprovider.LabelModelProvider] != "claude" {
		t.Errorf("labels = %v", secret.Labels)
	}
	if got := getModelProvider(t, c); got.Status.Phase != gibsonv1alpha1.ModelProviderPhaseReady || !got.Status.Ready {
		t.Errorf("status = %+v, want Ready", got.Status)
	}
	if len(src.calls) == 0 || src.calls[0] != "acme/anthropic-key/anthropic" {
		t.Errorf("daemon calls = %v", src.calls)
	}
}

// A rotated tenant secret reaches the Secret on the next reconcile.
func TestModelProvider_RotationUpdatesTheSecret(t *testing.T) {
	r, c := modelProviderTestRig(t, newModelProvider())
	src := anthropicCredentials()
	r.Credentials = src
	reconcileTwice(t, r)
	src.data["anthropic-key"] = map[string][]byte{"Authorization": []byte("sk-ant-2")}
	reconcileTwice(t, r)
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: "gibson-gateway", Name: "mp-acme-claude-credential"}
	if err := c.Get(context.Background(), key, &secret); err != nil {
		t.Fatal(err)
	}
	if got := string(secret.Data["Authorization"]); got != "sk-ant-2" {
		t.Errorf("Authorization = %q, want the rotated value", got)
	}
}

// A daemon error other than NotFound fails the reconcile, and the status text
// holds no credential.
func TestModelProvider_ADaemonErrorFails(t *testing.T) {
	r, c := modelProviderTestRig(t, newModelProvider())
	r.Credentials = &fakeModelCredentials{err: fmt.Errorf("dial: %w", clients.ErrUnreachable)}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: "claude"}}
	_, _ = r.Reconcile(context.Background(), req)
	if _, err := r.Reconcile(context.Background(), req); err == nil {
		t.Fatal("a daemon error gave no error")
	}
	if got := getModelProvider(t, c); got.Status.Phase != gibsonv1alpha1.ModelProviderPhaseFailed {
		t.Errorf("phase = %q, want Failed", got.Status.Phase)
	}
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: "gibson-gateway", Name: "mp-acme-claude-credential"}
	if err := c.Get(context.Background(), key, &secret); err == nil {
		t.Error("a Secret exists after a failed read")
	}
}

// A change of the spec reaches the backend, and a drifted backend is put back.
func TestModelProvider_UpdatesADriftedObject(t *testing.T) {
	r, c := modelProviderTestRig(t, newModelProvider())
	reconcileTwice(t, r)

	backend, _ := getObject(t, c, "AgentgatewayBackend", "agentgateway.dev/v1alpha1", "mp-acme-claude")
	_ = unstructured.SetNestedField(backend.Object, "Allow", "spec", "policies", "extAuth", "failureMode")
	if err := c.Update(context.Background(), backend); err != nil {
		t.Fatal(err)
	}
	reconcileTwice(t, r)
	fixed, _ := getObject(t, c, "AgentgatewayBackend", "agentgateway.dev/v1alpha1", "mp-acme-claude")
	if mode, _, _ := unstructured.NestedString(fixed.Object, "spec", "policies", "extAuth", "failureMode"); mode != "FailClosed" {
		t.Errorf("failure mode = %q, want FailClosed after the repair", mode)
	}
}

// A stale object of the provider is deleted. An object of another provider is not.
func TestModelProvider_DeletesAStaleObjectOnly(t *testing.T) {
	stale := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agentgateway.dev/v1alpha1", "kind": "AgentgatewayBackend",
		"metadata": map[string]any{
			"name": "mp-acme-claude-old", "namespace": "gibson-gateway",
			"labels": map[string]any{
				modelprovider.LabelManagedBy: "gibson-tenant-operator", modelprovider.LabelTenant: "acme",
				modelprovider.LabelModelProvider: "claude", modelprovider.LabelSourceNS: "tenant-acme",
			},
		},
		"spec": map[string]any{},
	}}
	other := stale.DeepCopy()
	other.SetName("mp-acme-other")
	other.SetLabels(map[string]string{
		modelprovider.LabelManagedBy: "gibson-tenant-operator", modelprovider.LabelTenant: "acme",
		modelprovider.LabelModelProvider: "other", modelprovider.LabelSourceNS: "tenant-acme",
	})
	r, c := modelProviderTestRig(t, newModelProvider(), stale, other)
	reconcileTwice(t, r)
	if _, ok := getObject(t, c, "AgentgatewayBackend", "agentgateway.dev/v1alpha1", "mp-acme-claude-old"); ok {
		t.Error("the stale backend was not deleted")
	}
	if _, ok := getObject(t, c, "AgentgatewayBackend", "agentgateway.dev/v1alpha1", "mp-acme-other"); !ok {
		t.Error("the backend of another provider was deleted")
	}
}

// A delete removes the gateway objects, then the finalizer.
func TestModelProvider_DeleteRemovesTheGatewayObjects(t *testing.T) {
	r, c := modelProviderTestRig(t, newModelProvider())
	r.Credentials = anthropicCredentials()
	reconcileTwice(t, r)
	if err := c.Delete(context.Background(), getModelProvider(t, c)); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: "claude"}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if _, ok := getObject(t, c, "AgentgatewayBackend", "agentgateway.dev/v1alpha1", "mp-acme-claude"); ok {
		t.Error("the backend is still there")
	}
	if _, ok := getObject(t, c, "HTTPRoute", "gateway.networking.k8s.io/v1", "mp-acme-claude"); ok {
		t.Error("the route is still there")
	}
	var gone corev1.Secret
	secretKey := types.NamespacedName{Namespace: "gibson-gateway", Name: "mp-acme-claude-credential"}
	if err := c.Get(context.Background(), secretKey, &gone); err == nil {
		t.Error("the credential Secret is still there")
	}
	var mp gibsonv1alpha1.ModelProvider
	if err := c.Get(context.Background(), req.NamespacedName, &mp); err == nil {
		t.Errorf("the provider still exists with finalizers %v", mp.Finalizers)
	}
}

// A provider that cannot be rendered fails, and the status says why.
func TestModelProvider_ARenderErrorIsReported(t *testing.T) {
	mp := newModelProvider()
	mp.Spec.Type = gibsonv1alpha1.ModelProviderOpenAICompatible
	mp.Spec.BaseURL = "http://insecure.example.com"
	r, c := modelProviderTestRig(t, mp)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: "claude"}}
	_, _ = r.Reconcile(context.Background(), req) // the finalizer
	if _, err := r.Reconcile(context.Background(), req); err == nil {
		t.Fatal("a render error gave no error")
	}
	got := getModelProvider(t, c)
	if got.Status.Phase != gibsonv1alpha1.ModelProviderPhaseFailed || got.Status.LastError == "" {
		t.Errorf("status = %+v, want Failed with a message", got.Status)
	}
}
