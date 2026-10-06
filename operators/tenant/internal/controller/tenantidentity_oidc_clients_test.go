package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	platformv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit/audittest"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/identity"
)

func platformBootstrap() *platformv1alpha1.PlatformBootstrap {
	pb := &platformv1alpha1.PlatformBootstrap{ObjectMeta: metav1.ObjectMeta{Name: "platform"}}
	pb.Spec.Zitadel.AdminTokenRef = platformv1alpha1.SecretKeyRef{Name: "zitadel-admin-pat", Namespace: "gibson"}
	pb.Spec.Zitadel.Project.Name = "gibson"
	return pb
}

// oidcFixture is a TenantIdentity with declared OIDC clients, the cluster's
// PlatformBootstrap, and a reconciler over a fake client.
type oidcFixture struct {
	c  client.Client
	r  *TenantIdentityReconciler
	ti *gibsonv1alpha1.TenantIdentity
}

func newOIDCFixture(t *testing.T, entries []gibsonv1alpha1.TenantIdentityOIDCClient, funcs interceptor.Funcs, extra ...client.Object) *oidcFixture {
	t.Helper()
	scheme := setupScheme(t)
	ti := newTenantIdentity("acme-identity", "acme")
	ti.UID = "ti-uid"
	ti.Spec.OIDCClients = entries
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&gibsonv1alpha1.TenantIdentity{}, &platformv1alpha1.OIDCClient{}).
		WithObjects(append([]client.Object{ti, platformBootstrap()}, extra...)...).
		WithInterceptorFuncs(funcs).
		Build()
	stub := &stubIdentityProvisioner{result: identity.Result{OrgID: "org-123", Slug: "acme"}}
	r := &TenantIdentityReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Audit: (&audittest.Sink{}).Emitter(t), Provisioner: stub, OrgMapping: &stubOrgMapping{}, ZitadelURL: "http://gibson-zitadel:8080"}
	return &oidcFixture{c: c, r: r, ti: ti}
}

// reconcile runs n passes and fails the test on an error.
func (f *oidcFixture) reconcile(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		if _, err := reconcileTI(t, f.r, "acme-identity"); err != nil {
			t.Fatalf("reconcile %d: %v", i+1, err)
		}
	}
}

func (f *oidcFixture) oidcClient(t *testing.T, name string) platformv1alpha1.OIDCClient {
	t.Helper()
	var oc platformv1alpha1.OIDCClient
	if err := f.c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: name}, &oc); err != nil {
		t.Fatalf("the OIDCClient %s does not exist: %v", name, err)
	}
	return oc
}

func (f *oidcFixture) identity(t *testing.T) gibsonv1alpha1.TenantIdentity {
	t.Helper()
	var got gibsonv1alpha1.TenantIdentity
	if err := f.c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity"}, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// markExists does what the platform-operator does once the Zitadel-side
// client is minted.
func (f *oidcFixture) markExists(t *testing.T, name string) {
	t.Helper()
	oc := f.oidcClient(t, name)
	oc.Status.Conditions = []metav1.Condition{{Type: platformv1alpha1.ConditionOIDCClientExists, Status: metav1.ConditionTrue, Reason: "Minted", LastTransitionTime: metav1.Now()}}
	if err := f.c.Status().Update(context.Background(), &oc); err != nil {
		t.Fatal(err)
	}
}

func twoDeclaredClients() []gibsonv1alpha1.TenantIdentityOIDCClient {
	return []gibsonv1alpha1.TenantIdentityOIDCClient{
		{Name: "portal", RedirectURIs: []string{"https://portal.acme.example/cb"}},
		{Name: "worker"},
	}
}

// TestTenantIdentity_MintsDeclaredOIDCClients proves spec.oidcClients[].Name
// and .RedirectURIs are read (gibson#597): each entry becomes a platform
// OIDCClient owned by the TenantIdentity, in the bootstrap's project. Before
// this, the controller counted the entries and never read one.
func TestTenantIdentity_MintsDeclaredOIDCClients(t *testing.T) {
	f := newOIDCFixture(t, twoDeclaredClients(), interceptor.Funcs{})
	// Pass 1 adds the finalizer; pass 2 provisions and mints.
	f.reconcile(t, 2)

	portal := f.oidcClient(t, "acme-identity-portal")
	if portal.Spec.ClientName != "acme/portal" || portal.Spec.ZitadelURL != "http://gibson-zitadel:8080" ||
		portal.Spec.ProjectRef.Name != "gibson" || portal.Spec.AdminTokenRef.Name != "zitadel-admin-pat" {
		t.Errorf("portal spec = %+v, want the bootstrap's issuer, token and project", portal.Spec)
	}
	if portal.Spec.ApplicationType != platformv1alpha1.OIDCAppTypeWeb || len(portal.Spec.RedirectURIs) != 1 ||
		portal.Spec.RedirectURIs[0] != "https://portal.acme.example/cb" {
		t.Errorf("portal is a web client with the declared redirect URI, got %+v", portal.Spec)
	}
	if !metav1.IsControlledBy(&portal, f.ti) {
		t.Error("the child must be owned by the TenantIdentity")
	}
	worker := f.oidcClient(t, "acme-identity-worker")
	if worker.Spec.ApplicationType != platformv1alpha1.OIDCAppTypeService || len(worker.Spec.RedirectURIs) != 0 {
		t.Errorf("an entry without redirect URIs is a service client, got %+v", worker.Spec)
	}
}

// TestTenantIdentity_OIDCClientsGateReadiness proves the oidc-client
// component stays pending until every child reports that its Zitadel-side
// client exists.
func TestTenantIdentity_OIDCClientsGateReadiness(t *testing.T) {
	f := newOIDCFixture(t, twoDeclaredClients(), interceptor.Funcs{})
	f.reconcile(t, 2)
	if got := f.identity(t); got.Status.Ready || componentState(got, "oidc-client") != "pending" {
		t.Fatalf("before the children exist the identity is not ready: ready=%v components=%+v", got.Status.Ready, got.Status.Components)
	}

	// The platform-operator mints both; the next pass reads ready.
	f.markExists(t, "acme-identity-portal")
	f.markExists(t, "acme-identity-worker")
	f.reconcile(t, 1)
	if got := f.identity(t); !got.Status.Ready || componentState(got, "oidc-client") != "ready" {
		t.Fatalf("after both children exist the identity is ready: ready=%v components=%+v", got.Status.Ready, got.Status.Components)
	}
}

// TestTenantIdentity_PrunesOnlyItsOwnOIDCClients proves a removed entry takes
// its child with it, and an OIDCClient that the TenantIdentity does not own
// stays.
func TestTenantIdentity_PrunesOnlyItsOwnOIDCClients(t *testing.T) {
	foreign := &platformv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{Name: "someone-elses", Namespace: "tenant-acme"}}
	f := newOIDCFixture(t, twoDeclaredClients(), interceptor.Funcs{}, foreign)
	f.reconcile(t, 2)

	got := f.identity(t)
	got.Spec.OIDCClients = got.Spec.OIDCClients[:1]
	if err := f.c.Update(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	f.reconcile(t, 1)

	var gone platformv1alpha1.OIDCClient
	if err := f.c.Get(context.Background(), types.NamespacedName{Namespace: "tenant-acme", Name: "acme-identity-worker"}, &gone); err == nil {
		t.Error("the worker child must be deleted once its entry is gone")
	}
	f.oidcClient(t, "acme-identity-portal")
	f.oidcClient(t, "someone-elses")
}

// TestTenantIdentity_OIDCClientFailuresAreNamed proves each API failure on
// the mint path fails the reconcile with an error that names the step, and
// lands in status.
func TestTenantIdentity_OIDCClientFailuresAreNamed(t *testing.T) {
	boom := errors.New("boom")
	orphan := func() client.Object {
		yes := true
		return &platformv1alpha1.OIDCClient{ObjectMeta: metav1.ObjectMeta{
			Name: "acme-identity-removed", Namespace: "tenant-acme",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: gibsonv1alpha1.GroupVersion.String(), Kind: "TenantIdentity", Name: "acme-identity", UID: "ti-uid", Controller: &yes}},
		}}
	}
	cases := []struct {
		name  string
		funcs interceptor.Funcs
		extra []client.Object
		want  string
	}{
		{
			name: "the bootstrap list fails",
			funcs: interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*platformv1alpha1.PlatformBootstrapList); ok {
					return boom
				}
				return c.List(ctx, list, opts...)
			}},
			want: "list PlatformBootstrap",
		},
		{
			name: "the child create fails",
			funcs: interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*platformv1alpha1.OIDCClient); ok {
					return boom
				}
				return c.Create(ctx, obj, opts...)
			}},
			want: "apply OIDCClient acme-identity-portal",
		},
		{
			name: "the children list fails",
			funcs: interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*platformv1alpha1.OIDCClientList); ok {
					return boom
				}
				return c.List(ctx, list, opts...)
			}},
			want: "list OIDCClients",
		},
		{
			name: "the delete of a removed child fails",
			funcs: interceptor.Funcs{Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if _, ok := obj.(*platformv1alpha1.OIDCClient); ok {
					return boom
				}
				return c.Delete(ctx, obj, opts...)
			}},
			extra: []client.Object{orphan()},
			want:  "delete OIDCClient acme-identity-removed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOIDCFixture(t, twoDeclaredClients()[:1], tc.funcs, tc.extra...)
			f.reconcile(t, 1)
			_, err := reconcileTI(t, f.r, "acme-identity")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one that names %q", err, tc.want)
			}
			if got := f.identity(t); got.Status.Ready || !strings.Contains(got.Status.LastError, tc.want) {
				t.Errorf("the failure must land in status: ready=%v lastError=%q", got.Status.Ready, got.Status.LastError)
			}
		})
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
	r := &TenantIdentityReconciler{Client: c, Scheme: scheme, Recorder: events.NewFakeRecorder(100), Audit: (&audittest.Sink{}).Emitter(t), Provisioner: stub, OrgMapping: &stubOrgMapping{}, ZitadelURL: "http://gibson-zitadel:8080"}
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
