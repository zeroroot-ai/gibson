// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/outsideagent"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

const testGatewayNS = "gibson-gateway"

type fakeOutsideRecords struct {
	byTenant map[string][]provision.DesiredOutsideAgent
	errFor   map[string]error
	asked    []string
}

func (f *fakeOutsideRecords) TenantOutsideAgents(_ context.Context, tenant string) ([]provision.DesiredOutsideAgent, error) {
	f.asked = append(f.asked, tenant)
	if err := f.errFor[tenant]; err != nil {
		return nil, err
	}
	return f.byTenant[tenant], nil
}

// fakeOutsideCredentials holds the credential of an agent by "tenant/name". An
// agent that is not in data gives clients.ErrNotFound.
type fakeOutsideCredentials struct{ data map[string]map[string][]byte }

func (f *fakeOutsideCredentials) OutsideAgentCredential(
	_ context.Context, tenant, name string,
) (map[string][]byte, error) {
	d, ok := f.data[tenant+"/"+name]
	if !ok {
		return nil, fmt.Errorf("get: %w", clients.ErrNotFound)
	}
	return d, nil
}

func tenantObject(name string, phase gibsonv1alpha1.TenantPhase) *gibsonv1alpha1.Tenant {
	t := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: name}}
	t.Status.Phase = phase
	return t
}

func outsideSyncRig(
	t *testing.T, rec *fakeOutsideRecords, creds *fakeOutsideCredentials, objs ...client.Object,
) (*OutsideAgentSyncRunnable, client.Client) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	all := append([]client.Object{
		tenantObject("acme", gibsonv1alpha1.TenantPhaseReady),
		tenantObject("beta", gibsonv1alpha1.TenantPhaseReady),
		tenantObject("newco", ""),
	}, objs...)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(all...).Build()
	return &OutsideAgentSyncRunnable{
		Client: c, Daemon: rec, Credentials: creds,
		Render: outsideagent.Config{Namespace: testGatewayNS, GatewayName: "agent-gateway"},
	}, c
}

func getGateway(t *testing.T, c client.Client, gvk schema.GroupVersionKind, name string) (*unstructured.Unstructured, bool) {
	t.Helper()
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gvk)
	err := c.Get(context.Background(), types.NamespacedName{Namespace: testGatewayNS, Name: name}, u)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("get %s %s: %v", gvk.Kind, name, err)
	}
	return u, err == nil
}

func hasSecret(t *testing.T, c client.Client, name string) (*corev1.Secret, bool) {
	t.Helper()
	var s corev1.Secret
	err := c.Get(context.Background(), types.NamespacedName{Namespace: testGatewayNS, Name: name}, &s)
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("get secret %s: %v", name, err)
	}
	return &s, err == nil
}

func TestOutsideAgentSync_CreatesBackendRouteAndSecret(t *testing.T) {
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "scout", A2AURL: "https://scout.example/a2a", CredentialSecret: "scout-key"}},
		// A tenant that is not ready is not read.
		"newco": {{Name: "x", A2AURL: "https://x.example"}},
	}}
	creds := &fakeOutsideCredentials{data: map[string]map[string][]byte{
		"acme/scout": {"Authorization": []byte("tok-1")},
	}}
	r, c := outsideSyncRig(t, rec, creds)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	for _, kind := range []schema.GroupVersionKind{agentgatewayBackendGVK, httpRouteGVK} {
		obj, ok := getGateway(t, c, kind, "oa-acme-scout")
		if !ok {
			t.Fatalf("%s oa-acme-scout was not created", kind.Kind)
		}
		if obj.GetLabels()[outsideagent.LabelTenant] != "acme" || obj.GetLabels()[outsideagent.LabelOutsideAgent] != "scout" {
			t.Errorf("%s labels = %v", kind.Kind, obj.GetLabels())
		}
	}
	secret, ok := hasSecret(t, c, "oa-acme-scout-credential")
	if !ok {
		t.Fatal("the credential Secret was not created")
	}
	if string(secret.Data["Authorization"]) != "tok-1" {
		t.Errorf("secret data keys = %d", len(secret.Data))
	}
	backend, _ := getGateway(t, c, agentgatewayBackendGVK, "oa-acme-scout")
	ref, _, _ := unstructured.NestedString(backend.Object, "spec", "policies", "auth", "secretRef", "name")
	if ref != "oa-acme-scout-credential" {
		t.Errorf("auth secretRef = %q", ref)
	}
	if len(rec.asked) != 2 {
		t.Errorf("records read for %v, want the two ready tenants", rec.asked)
	}
	if _, ok := getGateway(t, c, agentgatewayBackendGVK, "oa-newco-x"); ok {
		t.Error("a tenant that is not ready got a backend")
	}
}

func TestOutsideAgentSync_NoCredentialSecretMeansNoAuthPolicyAndNoSecret(t *testing.T) {
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "open", A2AURL: "https://open.example"}},
	}}
	r, c := outsideSyncRig(t, rec, &fakeOutsideCredentials{})
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	backend, ok := getGateway(t, c, agentgatewayBackendGVK, "oa-acme-open")
	if !ok {
		t.Fatal("the backend was not created")
	}
	if _, found, _ := unstructured.NestedMap(backend.Object, "spec", "policies", "auth"); found {
		t.Error("the backend has an auth policy")
	}
	if _, ok := hasSecret(t, c, "oa-acme-open-credential"); ok {
		t.Error("a Secret exists for an agent with no credential")
	}
}

func TestOutsideAgentSync_UpdatesWhenTheRecordOrTheCredentialChanges(t *testing.T) {
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "scout", A2AURL: "https://scout.example/a2a", CredentialSecret: "scout-key"}},
	}}
	creds := &fakeOutsideCredentials{data: map[string]map[string][]byte{"acme/scout": {"Authorization": []byte("tok-1")}}}
	r, c := outsideSyncRig(t, rec, creds)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	rec.byTenant["acme"][0].A2AURL = "https://moved.example:8443/v2"
	creds.data["acme/scout"] = map[string][]byte{"Authorization": []byte("tok-2")}
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	backend, _ := getGateway(t, c, agentgatewayBackendGVK, "oa-acme-scout")
	host, _, _ := unstructured.NestedString(backend.Object, "spec", "a2a", "host")
	if host != "moved.example" {
		t.Errorf("host = %q, want moved.example", host)
	}
	secret, _ := hasSecret(t, c, "oa-acme-scout-credential")
	if string(secret.Data["Authorization"]) != "tok-2" {
		t.Error("the rotated credential did not reach the Secret")
	}
}

func TestOutsideAgentSync_DeletesWhenTheRecordIsGone(t *testing.T) {
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {
			{Name: "scout", A2AURL: "https://scout.example", CredentialSecret: "k"},
			{Name: "keep", A2AURL: "https://keep.example"},
		},
	}}
	creds := &fakeOutsideCredentials{data: map[string]map[string][]byte{"acme/scout": {"Authorization": []byte("t")}}}
	r, c := outsideSyncRig(t, rec, creds)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	rec.byTenant["acme"] = rec.byTenant["acme"][1:]
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	for _, kind := range []schema.GroupVersionKind{agentgatewayBackendGVK, httpRouteGVK} {
		if _, ok := getGateway(t, c, kind, "oa-acme-scout"); ok {
			t.Errorf("the %s of the deleted record is still there", kind.Kind)
		}
		if _, ok := getGateway(t, c, kind, "oa-acme-keep"); !ok {
			t.Errorf("the %s of the kept record is gone", kind.Kind)
		}
	}
	if _, ok := hasSecret(t, c, "oa-acme-scout-credential"); ok {
		t.Error("the credential Secret of the deleted record is still there")
	}
}

func TestOutsideAgentSync_ADaemonErrorDeletesNothing(t *testing.T) {
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "scout", A2AURL: "https://scout.example", CredentialSecret: "k"}},
	}}
	creds := &fakeOutsideCredentials{data: map[string]map[string][]byte{"acme/scout": {"Authorization": []byte("t")}}}
	r, c := outsideSyncRig(t, rec, creds)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	rec.errFor = map[string]error{"acme": errors.New("daemon unavailable")}
	if err := r.Sync(context.Background()); err == nil {
		t.Fatal("the daemon error was not reported")
	}
	for _, kind := range []schema.GroupVersionKind{agentgatewayBackendGVK, httpRouteGVK} {
		if _, ok := getGateway(t, c, kind, "oa-acme-scout"); !ok {
			t.Errorf("the %s was deleted on a daemon error", kind.Kind)
		}
	}
	if _, ok := hasSecret(t, c, "oa-acme-scout-credential"); !ok {
		t.Error("the credential Secret was deleted on a daemon error")
	}
}

func TestOutsideAgentSync_AMissingTenantSecretKeepsWhatExists(t *testing.T) {
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "scout", A2AURL: "https://scout.example", CredentialSecret: "gone"}},
	}}
	creds := &fakeOutsideCredentials{data: map[string]map[string][]byte{"acme/scout": {"Authorization": []byte("t")}}}
	r, c := outsideSyncRig(t, rec, creds)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	delete(creds.data, "acme/scout")
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	if _, ok := getGateway(t, c, agentgatewayBackendGVK, "oa-acme-scout"); !ok {
		t.Error("the backend was deleted when the tenant secret went missing")
	}
}

func TestOutsideAgentSync_ATenantThatIsGoneLosesItsObjects(t *testing.T) {
	stale := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agentgateway.dev/v1alpha1", "kind": "AgentgatewayBackend",
		"metadata": map[string]any{
			"name": "oa-ghost-x", "namespace": testGatewayNS,
			"labels": map[string]any{
				outsideagent.LabelManagedBy: "gibson-tenant-operator", outsideagent.LabelTenant: "ghost",
				outsideagent.LabelOutsideAgent: "x",
			},
		},
		"spec": map[string]any{},
	}}
	r, c := outsideSyncRig(t, &fakeOutsideRecords{}, &fakeOutsideCredentials{}, stale)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if _, ok := getGateway(t, c, agentgatewayBackendGVK, "oa-ghost-x"); ok {
		t.Error("the backend of a tenant that does not exist is still there")
	}
}

func TestOutsideAgentSync_ARecordOfOneTenantNeverRendersAnObjectOfAnother(t *testing.T) {
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "scout", A2AURL: "https://a.example"}},
		"beta": {{Name: "other", A2AURL: "https://b.example"}},
	}}
	r, c := outsideSyncRig(t, rec, &fakeOutsideCredentials{})
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	for name, tenant := range map[string]string{"oa-acme-scout": "acme", "oa-beta-other": "beta"} {
		for _, kind := range []schema.GroupVersionKind{agentgatewayBackendGVK, httpRouteGVK} {
			obj, ok := getGateway(t, c, kind, name)
			if !ok {
				t.Fatalf("%s %s is missing", kind.Kind, name)
			}
			if obj.GetLabels()[outsideagent.LabelTenant] != tenant {
				t.Errorf("%s %s has the tenant label %q, want %q", kind.Kind, name, obj.GetLabels()[outsideagent.LabelTenant], tenant)
			}
		}
	}
	if _, ok := getGateway(t, c, agentgatewayBackendGVK, "oa-acme-other"); ok {
		t.Error("the record of beta rendered an object of acme")
	}
	route, _ := getGateway(t, c, httpRouteGVK, "oa-acme-scout")
	rules, _, _ := unstructured.NestedSlice(route.Object, "spec", "rules")
	headers, _, _ := unstructured.NestedSlice(rules[0].(map[string]any), "matches")
	for _, h := range headers[0].(map[string]any)["headers"].([]any) {
		hm := h.(map[string]any)
		if hm["name"] == "x-gibson-route-tenant" && hm["value"] != "acme" {
			t.Errorf("the route of acme matches the tenant %v", hm["value"])
		}
	}
}

func TestOutsideAgentSync_RefusesToTakeAnObjectOfAnotherOwner(t *testing.T) {
	// Two names can give one object name. The object here is named for the agent
	// b-c of acme, and it belongs to the agent c of beta.
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {{Name: "b-c", A2AURL: "https://a.example"}},
		"beta": {{Name: "c", A2AURL: "https://owner.example"}},
	}}
	other := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "agentgateway.dev/v1alpha1", "kind": "AgentgatewayBackend",
		"metadata": map[string]any{
			"name": "oa-acme-b-c", "namespace": testGatewayNS,
			"labels": map[string]any{
				outsideagent.LabelManagedBy: "gibson-tenant-operator", outsideagent.LabelTenant: "beta",
				outsideagent.LabelOutsideAgent: "c",
			},
		},
		"spec": map[string]any{"a2a": map[string]any{"host": "owner.example", "port": int64(443)}},
	}}
	r, c := outsideSyncRig(t, rec, &fakeOutsideCredentials{}, other)
	if err := r.Sync(context.Background()); err == nil {
		t.Fatal("the collision was not reported")
	}
	backend, _ := getGateway(t, c, agentgatewayBackendGVK, "oa-acme-b-c")
	if host, _, _ := unstructured.NestedString(backend.Object, "spec", "a2a", "host"); host != "owner.example" {
		t.Errorf("the object of the other owner changed: host = %q", host)
	}
}

func TestOutsideAgentSync_WritesTheCABundleAndNamesItInTheBackend(t *testing.T) {
	rec := &fakeOutsideRecords{byTenant: map[string][]provision.DesiredOutsideAgent{
		"acme": {
			{Name: "both", A2AURL: "https://both.example", CredentialSecret: "k", CABundleSecret: "ca"},
			{Name: "ca-only", A2AURL: "https://ca.example", CABundleSecret: "ca"},
		},
	}}
	creds := &fakeOutsideCredentials{data: map[string]map[string][]byte{
		"acme/both":    {"Authorization": []byte("tok"), "ca.crt": []byte("PEM")},
		"acme/ca-only": {"ca.crt": []byte("PEM")},
	}}
	r, c := outsideSyncRig(t, rec, creds)
	if err := r.Sync(context.Background()); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	for _, name := range []string{"both", "ca-only"} {
		secret, ok := hasSecret(t, c, "oa-acme-"+name+"-credential")
		if !ok || string(secret.Data["ca.crt"]) != "PEM" {
			t.Fatalf("%s: the Secret has no CA bundle", name)
		}
		backend, _ := getGateway(t, c, agentgatewayBackendGVK, "oa-acme-"+name)
		refs, found, _ := unstructured.NestedSlice(backend.Object, "spec", "policies", "tls", "caCertificateRefs")
		if !found || len(refs) != 1 {
			t.Fatalf("%s: caCertificateRefs = %v", name, refs)
		}
		ref := refs[0].(map[string]any)
		if ref["kind"] != "Secret" || ref["name"] != "oa-acme-"+name+"-credential" || ref["key"] != "ca.crt" {
			t.Errorf("%s: ref = %v", name, ref)
		}
	}
	both, _ := getGateway(t, c, agentgatewayBackendGVK, "oa-acme-both")
	if _, found, _ := unstructured.NestedMap(both.Object, "spec", "policies", "auth"); !found {
		t.Error("the agent with a credential has no auth policy")
	}
	only, _ := getGateway(t, c, agentgatewayBackendGVK, "oa-acme-ca-only")
	if _, found, _ := unstructured.NestedMap(only.Object, "spec", "policies", "auth"); found {
		t.Error("the agent with no credential has an auth policy")
	}
}
