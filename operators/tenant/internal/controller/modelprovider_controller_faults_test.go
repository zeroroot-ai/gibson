// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/modelprovider"
)

var errInjected = errors.New("injected client failure")

// faultRig is modelProviderTestRig with a client that fails where the funcs say.
func faultRig(
	t *testing.T, mp *gibsonv1alpha1.ModelProvider, funcs interceptor.Funcs, extra ...client.Object,
) (*ModelProviderReconciler, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(append([]client.Object{mp}, extra...)...).
		WithStatusSubresource(&gibsonv1alpha1.ModelProvider{}).WithInterceptorFuncs(funcs).Build()
	r := &ModelProviderReconciler{
		Client: c, Scheme: scheme,
		Render:      modelprovider.Config{Namespace: "gibson-gateway", GatewayName: "model-gateway"},
		Credentials: anthropicCredentials(),
	}
	return r, c
}

// finalizedModelProvider is a provider that has its finalizer, so a reconcile
// goes straight to the render.
func finalizedModelProvider() *gibsonv1alpha1.ModelProvider {
	mp := newModelProvider()
	mp.Finalizers = []string{gibsonv1alpha1.ModelProviderFinalizer}
	return mp
}

func reconcileModelProvider(r *ModelProviderReconciler) (ctrl.Result, error) {
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "tenant-acme", Name: "claude"},
	})
}

func isUnstructured(obj client.Object) bool {
	_, ok := obj.(*unstructured.Unstructured)
	return ok
}

func TestModelProvider_ClientFailuresFailTheReconcile(t *testing.T) {
	tests := []struct {
		name     string
		mp       *gibsonv1alpha1.ModelProvider
		funcs    interceptor.Funcs
		wantErr  string
		wantFail bool
	}{
		{
			name: "the provider cannot be read",
			mp:   finalizedModelProvider(),
			funcs: interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				if _, ok := obj.(*gibsonv1alpha1.ModelProvider); ok {
					return errInjected
				}
				return c.Get(ctx, key, obj, opts...)
			}},
			wantErr: errInjected.Error(),
		},
		{
			name: "the finalizer cannot be added",
			mp:   newModelProvider(),
			funcs: interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object,
				opts ...client.UpdateOption,
			) error {
				return errInjected
			}},
			wantErr: "add the finalizer",
		},
		{
			name: "a gateway object cannot be created",
			mp:   finalizedModelProvider(),
			funcs: interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object,
				opts ...client.CreateOption,
			) error {
				if isUnstructured(obj) {
					return errInjected
				}
				return c.Create(ctx, obj, opts...)
			}},
			wantErr:  "create AgentgatewayBackend",
			wantFail: true,
		},
		{
			name: "a gateway object cannot be read",
			mp:   finalizedModelProvider(),
			funcs: interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				if isUnstructured(obj) {
					return errInjected
				}
				return c.Get(ctx, key, obj, opts...)
			}},
			wantErr:  "read AgentgatewayBackend",
			wantFail: true,
		},
		{
			name: "the owned objects cannot be listed",
			mp:   finalizedModelProvider(),
			funcs: interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList,
				opts ...client.ListOption,
			) error {
				return errInjected
			}},
			wantErr:  "list AgentgatewayBackend",
			wantFail: true,
		},
		{
			name: "the credential Secret cannot be read",
			mp:   finalizedModelProvider(),
			funcs: interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errInjected
				}
				return c.Get(ctx, key, obj, opts...)
			}},
			wantErr:  "read the credential Secret",
			wantFail: true,
		},
		{
			name: "the credential Secret cannot be created",
			mp:   finalizedModelProvider(),
			funcs: interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object,
				opts ...client.CreateOption,
			) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errInjected
				}
				return c.Create(ctx, obj, opts...)
			}},
			wantErr:  "create the credential Secret",
			wantFail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, c := faultRig(t, tt.mp, tt.funcs)
			_, err := reconcileModelProvider(r)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one that holds %q", err, tt.wantErr)
			}
			if tt.wantFail {
				got := getModelProvider(t, c)
				if got.Status.Phase != gibsonv1alpha1.ModelProviderPhaseFailed || got.Status.Ready ||
					!strings.Contains(got.Status.LastError, tt.wantErr) {
					t.Errorf("status = %+v, want Failed with the cause", got.Status)
				}
			}
		})
	}
}

func TestModelProvider_AnEmptyCredentialFromTheDaemonFails(t *testing.T) {
	r, c := faultRig(t, finalizedModelProvider(), interceptor.Funcs{})
	r.Credentials = &fakeModelCredentials{data: map[string]map[string][]byte{"anthropic-key": {}}}
	_, err := reconcileModelProvider(r)
	if err == nil || !strings.Contains(err.Error(), "empty credential") {
		t.Fatalf("error = %v", err)
	}
	var secret corev1.Secret
	key := types.NamespacedName{Namespace: "gibson-gateway", Name: "mp-acme-claude-credential"}
	if getErr := c.Get(context.Background(), key, &secret); getErr == nil {
		t.Error("a credential Secret was written from an empty answer")
	}
}

// A gateway object that lost its labels is repaired, and a credential Secret
// with other data and no labels gets the data of the daemon and the labels.
func TestModelProvider_RepairsObjectsThatLostLabelsAndData(t *testing.T) {
	stale := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gibson-gateway", Name: "mp-acme-claude-credential"},
		Data:       map[string][]byte{"Authorization": []byte("old"), "extra": []byte("x")},
	}
	r, c := faultRig(t, finalizedModelProvider(), interceptor.Funcs{}, stale)
	if _, err := reconcileModelProvider(r); err != nil {
		t.Fatal(err)
	}
	var secret corev1.Secret
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(stale), &secret); err != nil {
		t.Fatal(err)
	}
	if len(secret.Data) != 1 || string(secret.Data["Authorization"]) != "sk-ant-1" {
		t.Errorf("secret data = %v, want only the daemon content", secret.Data)
	}
	if secret.Labels[modelprovider.LabelModelProvider] != "claude" {
		t.Errorf("secret labels = %v", secret.Labels)
	}

	backend, ok := getObject(t, c, "AgentgatewayBackend", "agentgateway.dev/v1alpha1", "mp-acme-claude")
	if !ok {
		t.Fatal("the backend was not created")
	}
	backend.SetLabels(nil)
	if err := c.Update(context.Background(), backend); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileModelProvider(r); err != nil {
		t.Fatal(err)
	}
	backend, _ = getObject(t, c, "AgentgatewayBackend", "agentgateway.dev/v1alpha1", "mp-acme-claude")
	if backend.GetLabels()[modelprovider.LabelModelProvider] != "claude" {
		t.Errorf("backend labels = %v, want the owner labels back", backend.GetLabels())
	}
}

func TestModelProvider_UpdateFailuresOnDriftedObjectsAreReported(t *testing.T) {
	// First reconcile with a healthy client, then break Update and drift both kinds.
	failing := false
	funcs := interceptor.Funcs{Update: func(ctx context.Context, c client.WithWatch, obj client.Object,
		opts ...client.UpdateOption,
	) error {
		if failing {
			if _, isMP := obj.(*gibsonv1alpha1.ModelProvider); !isMP {
				return errInjected
			}
		}
		return c.Update(ctx, obj, opts...)
	}}
	r, c := faultRig(t, finalizedModelProvider(), funcs)
	if _, err := reconcileModelProvider(r); err != nil {
		t.Fatal(err)
	}
	failing = true

	var secret corev1.Secret
	key := types.NamespacedName{Namespace: "gibson-gateway", Name: "mp-acme-claude-credential"}
	if err := c.Get(context.Background(), key, &secret); err != nil {
		t.Fatal(err)
	}
	secret.Data = map[string][]byte{"Authorization": []byte("drift")}
	failing = false
	if err := c.Update(context.Background(), &secret); err != nil {
		t.Fatal(err)
	}
	failing = true
	if _, err := reconcileModelProvider(r); err == nil || !strings.Contains(err.Error(), "update the credential Secret") {
		t.Fatalf("secret update error = %v", err)
	}

	backend, _ := getObject(t, c, "AgentgatewayBackend", "agentgateway.dev/v1alpha1", "mp-acme-claude")
	backend.SetLabels(nil)
	failing = false
	if err := c.Update(context.Background(), backend); err != nil {
		t.Fatal(err)
	}
	failing = true
	if _, err := reconcileModelProvider(r); err == nil || !strings.Contains(err.Error(), "update AgentgatewayBackend") {
		t.Fatalf("backend update error = %v", err)
	}
}

func TestModelProvider_AStaleObjectThatCannotBeDeletedFails(t *testing.T) {
	r, c := faultRig(t, finalizedModelProvider(), interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch,
		obj client.Object, opts ...client.DeleteOption,
	) error {
		return errInjected
	}})
	if _, err := reconcileModelProvider(r); err != nil {
		t.Fatal(err)
	}
	stale := &unstructured.Unstructured{}
	stale.SetAPIVersion("gateway.networking.k8s.io/v1")
	stale.SetKind("HTTPRoute")
	stale.SetNamespace("gibson-gateway")
	stale.SetName("mp-acme-claude-old")
	stale.SetLabels(map[string]string{
		modelprovider.LabelManagedBy: "gibson-tenant-operator", modelprovider.LabelTenant: "acme",
		modelprovider.LabelModelProvider: "claude", modelprovider.LabelSourceNS: "tenant-acme",
	})
	if err := c.Create(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileModelProvider(r); err == nil || !strings.Contains(err.Error(), "delete the stale HTTPRoute") {
		t.Fatalf("error = %v", err)
	}
}

func TestModelProvider_StatusPatchFailureDoesNotFailTheReconcile(t *testing.T) {
	r, _ := faultRig(t, finalizedModelProvider(), interceptor.Funcs{SubResourcePatch: func(
		ctx context.Context, c client.Client, subResourceName string, obj client.Object,
		patch client.Patch, opts ...client.SubResourcePatchOption,
	) error {
		return errInjected
	}})
	res, err := reconcileModelProvider(r)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != modelProviderResync {
		t.Errorf("requeue = %v, want %v", res.RequeueAfter, modelProviderResync)
	}
}

func deletingModelProvider() *gibsonv1alpha1.ModelProvider {
	mp := finalizedModelProvider()
	now := metav1.Now()
	mp.DeletionTimestamp = &now
	return mp
}

func TestModelProvider_DeleteFailuresKeepTheFinalizer(t *testing.T) {
	tests := []struct {
		name    string
		funcs   interceptor.Funcs
		wantErr string
	}{
		{
			name: "the owned objects cannot be listed",
			funcs: interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList,
				opts ...client.ListOption,
			) error {
				return errInjected
			}},
			wantErr: "list AgentgatewayBackend",
		},
		{
			name: "the credential Secret cannot be deleted",
			funcs: interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object,
				opts ...client.DeleteOption,
			) error {
				if _, ok := obj.(*corev1.Secret); ok {
					return errInjected
				}
				return c.Delete(ctx, obj, opts...)
			}},
			wantErr: "delete the credential Secret",
		},
		{
			name: "the finalizer cannot be removed",
			funcs: interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object,
				patch client.Patch, opts ...client.PatchOption,
			) error {
				return errInjected
			}},
			wantErr: errInjected.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := faultRig(t, deletingModelProvider(), tt.funcs)
			_, err := reconcileModelProvider(r)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one that holds %q", err, tt.wantErr)
			}
		})
	}
}

func TestModelProvider_DeleteOfAnOwnedObjectThatFailsKeepsTheFinalizer(t *testing.T) {
	owned := &unstructured.Unstructured{}
	owned.SetAPIVersion("agentgateway.dev/v1alpha1")
	owned.SetKind("AgentgatewayBackend")
	owned.SetNamespace("gibson-gateway")
	owned.SetName("mp-acme-claude")
	owned.SetLabels(map[string]string{
		modelprovider.LabelManagedBy: "gibson-tenant-operator", modelprovider.LabelTenant: "acme",
		modelprovider.LabelModelProvider: "claude", modelprovider.LabelSourceNS: "tenant-acme",
	})
	r, _ := faultRig(t, deletingModelProvider(), interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch,
		obj client.Object, opts ...client.DeleteOption,
	) error {
		return errInjected
	}}, owned)
	_, err := reconcileModelProvider(r)
	if err == nil || !strings.Contains(err.Error(), "delete AgentgatewayBackend mp-acme-claude") {
		t.Fatalf("error = %v", err)
	}
}

func TestModelProvider_DeleteWithoutOurFinalizerDoesNothing(t *testing.T) {
	r, _ := faultRig(t, newModelProvider(), interceptor.Funcs{})
	res, err := r.reconcileDelete(context.Background(), newModelProvider())
	if err != nil || res != (ctrl.Result{}) {
		t.Fatalf("reconcileDelete = %+v, %v", res, err)
	}
}

func TestModelProvider_SetupWithManager(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	mgr, err := manager.New(&rest.Config{Host: "localhost:1"}, manager.Options{
		Scheme:     scheme,
		Metrics:    metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	valid := modelprovider.Config{Namespace: "gibson-gateway", GatewayName: "model-gateway"}

	bad := &ModelProviderReconciler{Client: mgr.GetClient(), Credentials: anthropicCredentials()}
	if err := bad.SetupWithManager(mgr); err == nil || !strings.Contains(err.Error(), "namespace is required") {
		t.Errorf("invalid render config error = %v", err)
	}
	noSource := &ModelProviderReconciler{Client: mgr.GetClient(), Render: valid}
	noSource.Credentials = nil
	err = noSource.SetupWithManager(mgr)
	if err == nil || !strings.Contains(err.Error(), "credential source is required") {
		t.Errorf("missing credential source error = %v", err)
	}
	ok := &ModelProviderReconciler{Client: mgr.GetClient(), Render: valid, Credentials: anthropicCredentials()}
	if err := ok.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}
	if ok.Recorder == nil {
		t.Error("the recorder was not set from the manager")
	}
}
