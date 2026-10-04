package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	platformv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/identity"
)

func platformBootstrap() *platformv1alpha1.PlatformBootstrap {
	pb := &platformv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	pb.Spec.Zitadel.Issuer = "https://idp.example.test"
	pb.Spec.Zitadel.AdminTokenRef = platformv1alpha1.SecretKeyRef{Name: "zitadel-admin-pat", Namespace: "gibson"}
	pb.Spec.Zitadel.Project.Name = "gibson"
	return pb
}

// TestTenantIdentity_MintsDeclaredOIDCClients proves spec.oidcClients[].Name
// and .RedirectURIs are read (gibson#597): each entry becomes a platform
// OIDCClient owned by the TenantIdentity, in the bootstrap's project, and
// the oidc-client component stays pending until the child reports its
// Zitadel-side client exists. Before this, the controller counted the
// entries and never read one.
func TestTenantIdentity_MintsDeclaredOIDCClients(t *testing.T) {
	scheme := setupScheme(t)
	ti := newTenantIdentity("acme-identity", "acme")
	ti.Spec.OIDCClients = []gibsonv1alpha1.TenantIdentityOIDCClient{
		{Name: "portal", RedirectURIs: []string{"https://portal.acme.example/cb"}},
		{Name: "worker"},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantIdentity{}, &platformv1alpha1.OIDCClient{}).
		WithObjects(ti, platformBootstrap()).
		Build()
	stub := &stubIdentityProvisioner{result: identity.Result{OrgID: "org-123", Slug: "acme"}}
	r := &TenantIdentityReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub, OrgMapping: &stubOrgMapping{}}

	// Pass 1 adds the finalizer; pass 2 provisions and mints.
	for i := 0; i < 2; i++ {
		if _, err := reconcileTI(t, r, "acme-identity"); err != nil {
			t.Fatalf("reconcile %d: %v", i+1, err)
		}
	}

	var portal platformv1alpha1.OIDCClient
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity-portal"}, &portal); err != nil {
		t.Fatalf("the portal OIDCClient was not minted: %v", err)
	}
	if portal.Spec.ClientName != "acme/portal" || portal.Spec.ZitadelIssuer != "https://idp.example.test" ||
		portal.Spec.ProjectRef.Name != "gibson" || portal.Spec.AdminTokenRef.Name != "zitadel-admin-pat" {
		t.Errorf("portal spec = %+v, want the bootstrap's issuer, token and project", portal.Spec)
	}
	if portal.Spec.ApplicationType != platformv1alpha1.OIDCAppTypeWeb || len(portal.Spec.RedirectURIs) != 1 ||
		portal.Spec.RedirectURIs[0] != "https://portal.acme.example/cb" {
		t.Errorf("portal is a web client with the declared redirect URI, got %+v", portal.Spec)
	}
	if !metav1.IsControlledBy(&portal, ti) {
		t.Error("the child must be owned by the TenantIdentity")
	}
	var worker platformv1alpha1.OIDCClient
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity-worker"}, &worker); err != nil {
		t.Fatalf("the worker OIDCClient was not minted: %v", err)
	}
	if worker.Spec.ApplicationType != platformv1alpha1.OIDCAppTypeService || len(worker.Spec.RedirectURIs) != 0 {
		t.Errorf("an entry without redirect URIs is a service client, got %+v", worker.Spec)
	}

	var got gibsonv1alpha1.TenantIdentity
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Ready || componentState(got, "oidc-client") != "pending" {
		t.Fatalf("before the children exist the identity is not ready: ready=%v components=%+v", got.Status.Ready, got.Status.Components)
	}

	// The platform-operator mints both; the next pass reads ready.
	for _, name := range []string{"acme-identity-portal", "acme-identity-worker"} {
		var oc platformv1alpha1.OIDCClient
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: name}, &oc); err != nil {
			t.Fatal(err)
		}
		oc.Status.Conditions = []metav1.Condition{{Type: platformv1alpha1.ConditionOIDCClientExists, Status: metav1.ConditionTrue, Reason: "Minted", LastTransitionTime: metav1.Now()}}
		if err := c.Status().Update(context.Background(), &oc); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := reconcileTI(t, r, "acme-identity"); err != nil {
		t.Fatalf("reconcile 3: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Status.Ready || componentState(got, "oidc-client") != "ready" {
		t.Fatalf("after both children exist the identity is ready: ready=%v components=%+v", got.Status.Ready, got.Status.Components)
	}

	// Removing an entry removes its child.
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got); err != nil {
		t.Fatal(err)
	}
	got.Spec.OIDCClients = got.Spec.OIDCClients[:1]
	if err := c.Update(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileTI(t, r, "acme-identity"); err != nil {
		t.Fatalf("reconcile 4: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity-worker"}, &worker); err == nil {
		t.Error("the worker child must be deleted once its entry is gone")
	}
}

// TestTenantIdentity_OIDCClientsNeedTheBootstrap proves a declared client
// with no PlatformBootstrap to copy the issuer, token and project from is a
// named failure, not a silently unminted client.
func TestTenantIdentity_OIDCClientsNeedTheBootstrap(t *testing.T) {
	scheme := setupScheme(t)
	ti := newTenantIdentity("acme-identity", "acme")
	ti.Spec.OIDCClients = []gibsonv1alpha1.TenantIdentityOIDCClient{{Name: "portal"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&gibsonv1alpha1.TenantIdentity{}).WithObjects(ti).Build()
	stub := &stubIdentityProvisioner{result: identity.Result{OrgID: "org-123", Slug: "acme"}}
	r := &TenantIdentityReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Provisioner: stub, OrgMapping: &stubOrgMapping{}}
	if _, err := reconcileTI(t, r, "acme-identity"); err != nil {
		t.Fatal(err)
	}
	_, err := reconcileTI(t, r, "acme-identity")
	if err == nil {
		t.Fatal("expected an error naming the missing PlatformBootstrap")
	}
	var got gibsonv1alpha1.TenantIdentity
	if gerr := c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got); gerr != nil {
		t.Fatal(gerr)
	}
	if got.Status.Ready || got.Status.LastError == "" {
		t.Errorf("the failure must land in status: ready=%v lastError=%q", got.Status.Ready, got.Status.LastError)
	}
}

func componentState(ti gibsonv1alpha1.TenantIdentity, name string) string {
	for _, c := range ti.Status.Components {
		if c.Name == name {
			return c.State
		}
	}
	return ""
}
