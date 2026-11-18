// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

type fakeRecords struct {
	byTenant map[string][]provision.DesiredModelProvider
	err      error
}

func (f *fakeRecords) TenantModelProviders(_ context.Context, tenant string) ([]provision.DesiredModelProvider, []string, error) {
	return f.byTenant[tenant], []string{"emb: voyage is not a provider type"}, f.err
}

func syncRig(t *testing.T, records *fakeRecords, objs ...client.Object) (*ModelProviderSyncRunnable, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ready := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	ready.Status.Phase = gibsonv1alpha1.TenantPhaseReady
	pending := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "newco"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(append([]client.Object{ready, pending}, objs...)...).Build()
	return &ModelProviderSyncRunnable{Client: c, Daemon: records}, c
}

func getMP(t *testing.T, c client.Client, name string) (*gibsonv1alpha1.ModelProvider, bool) {
	t.Helper()
	var mp gibsonv1alpha1.ModelProvider
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: name}, &mp)
	return &mp, err == nil
}

func TestSync_CreatesOneModelProviderForEachRecord(t *testing.T) {
	rec := &fakeRecords{byTenant: map[string][]provision.DesiredModelProvider{
		"acme": {{Name: "claude", Type: "anthropic", CredentialSecret: "provider_cred:claude"}},
		// A tenant that is not ready is not read.
		"newco": {{Name: "x", Type: "openai", CredentialSecret: "provider_cred:x"}},
	}}
	r, c := syncRig(t, rec)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	mp, ok := getMP(t, c, "claude")
	if !ok {
		t.Fatal("the ModelProvider was not created")
	}
	if mp.Spec.TenantID != "acme" || mp.Spec.Type != "anthropic" || mp.Spec.CredentialSecret != "provider_cred:claude" {
		t.Errorf("spec = %+v", mp.Spec)
	}
	if mp.Labels[LabelModelProviderFromRecord] != "true" {
		t.Errorf("labels = %v", mp.Labels)
	}
	var all gibsonv1alpha1.ModelProviderList
	if err := c.List(context.Background(), &all); err != nil || len(all.Items) != 1 {
		t.Errorf("%d ModelProviders, want 1 (err %v)", len(all.Items), err)
	}
}

func TestSync_UpdatesAndRemoves(t *testing.T) {
	old := &gibsonv1alpha1.ModelProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "local", Namespace: "tenant-acme", Labels: map[string]string{LabelModelProviderFromRecord: "true"}},
		Spec: gibsonv1alpha1.ModelProviderSpec{
			TenantID: "acme", Type: gibsonv1alpha1.ModelProviderOpenAICompatible,
			BaseURL: "https://old.example", CredentialSecret: "provider_cred:local",
		},
	}
	gone := &gibsonv1alpha1.ModelProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "gone", Namespace: "tenant-acme", Labels: map[string]string{LabelModelProviderFromRecord: "true"}},
		Spec:       gibsonv1alpha1.ModelProviderSpec{TenantID: "acme", Type: gibsonv1alpha1.ModelProviderOpenAI, CredentialSecret: "provider_cred:gone"},
	}
	// A ModelProvider that a person made by hand has no label. The loop keeps it.
	manual := &gibsonv1alpha1.ModelProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "manual", Namespace: "tenant-acme"},
		Spec:       gibsonv1alpha1.ModelProviderSpec{TenantID: "acme", Type: gibsonv1alpha1.ModelProviderOpenAI, CredentialSecret: "s"},
	}
	rec := &fakeRecords{byTenant: map[string][]provision.DesiredModelProvider{
		"acme": {{Name: "local", Type: "openai-compatible", BaseURL: "https://new.example", CredentialSecret: "provider_cred:local"}},
	}}
	r, c := syncRig(t, rec, old, gone, manual)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mp, _ := getMP(t, c, "local"); mp.Spec.BaseURL != "https://new.example" {
		t.Errorf("base URL = %q", mp.Spec.BaseURL)
	}
	if _, ok := getMP(t, c, "gone"); ok {
		t.Error("the ModelProvider of a record that is gone was not removed")
	}
	if _, ok := getMP(t, c, "manual"); !ok {
		t.Error("a ModelProvider without the label was removed")
	}
}

// The type of a ModelProvider is immutable. A changed type deletes the old one.
// A create in the same pass is refused while the finalizer holds the old one, and
// a later pass creates the new one.
func TestSync_ATypeChangeReplacesTheModelProvider(t *testing.T) {
	old := &gibsonv1alpha1.ModelProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "tenant-acme", Labels: map[string]string{LabelModelProviderFromRecord: "true"}},
		Spec:       gibsonv1alpha1.ModelProviderSpec{TenantID: "acme", Type: gibsonv1alpha1.ModelProviderOpenAI, CredentialSecret: "provider_cred:p"},
	}
	rec := &fakeRecords{byTenant: map[string][]provision.DesiredModelProvider{
		"acme": {{Name: "p", Type: "anthropic", CredentialSecret: "provider_cred:p"}},
	}}
	r, c := syncRig(t, rec, old)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mp, ok := getMP(t, c, "p"); !ok || mp.Spec.Type != "anthropic" {
		t.Errorf("the ModelProvider of the new type was not created: %+v", mp)
	}
}

// A daemon error changes nothing. No ModelProvider is deleted on an error.
func TestSync_ADaemonErrorDeletesNothing(t *testing.T) {
	old := &gibsonv1alpha1.ModelProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "keep", Namespace: "tenant-acme", Labels: map[string]string{LabelModelProviderFromRecord: "true"}},
		Spec:       gibsonv1alpha1.ModelProviderSpec{TenantID: "acme", Type: gibsonv1alpha1.ModelProviderOpenAI, CredentialSecret: "provider_cred:keep"},
	}
	r, c := syncRig(t, &fakeRecords{err: errors.New("daemon down")}, old)
	if err := r.Sync(context.Background()); err == nil {
		t.Fatal("a daemon error gave no error")
	}
	if _, ok := getMP(t, c, "keep"); !ok {
		t.Error("a ModelProvider was removed on a daemon error")
	}
}

func TestSync_ANameThatIsNotAKubernetesNameIsSkipped(t *testing.T) {
	rec := &fakeRecords{byTenant: map[string][]provision.DesiredModelProvider{
		"acme": {{Name: "My Claude", Type: "anthropic", CredentialSecret: "provider_cred:My Claude"}},
	}}
	r, c := syncRig(t, rec)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	var all gibsonv1alpha1.ModelProviderList
	if err := c.List(context.Background(), &all); err != nil || len(all.Items) != 0 {
		t.Errorf("%d ModelProviders, want 0", len(all.Items))
	}
}
