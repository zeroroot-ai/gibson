// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// stubCatalogGate answers the platform catalog gate in tests. The zero value
// allows every entry (the seeded steady state); denied lists object refs that
// answer false; err fails every call (the fail-closed path).
type stubCatalogGate struct {
	denied []string
	err    error
}

func (g *stubCatalogGate) allowedObject(object string) bool {
	for _, d := range g.denied {
		if d == object {
			return false
		}
	}
	return true
}

func (g *stubCatalogGate) Check(_ context.Context, _, _, object string) (bool, error) {
	if g.err != nil {
		return false, g.err
	}
	return g.allowedObject(object), nil
}

func (g *stubCatalogGate) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	if g.err != nil {
		return nil, g.err
	}
	out := make([]bool, len(checks))
	for i, c := range checks {
		out[i] = g.allowedObject(c.Object)
	}
	return out, nil
}

// newConnectorService builds a ConnectorService over a fake ConnectorInstance
// client seeded with the given objects and an allow-all catalog gate. The
// scheme knows the ConnectorInstance kinds so the fake client can create,
// list and delete them.
func newConnectorService(t *testing.T, seed ...client.Object) *ConnectorService {
	t.Helper()
	return newConnectorServiceWithGate(t, &stubCatalogGate{}, seed...)
}

func newConnectorServiceWithGate(t *testing.T, gate CatalogGate, seed ...client.Object) *ConnectorService {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, connectorv1alpha1.AddToScheme(scheme))
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(seed...).Build()
	return NewConnectorService(kube, gate)
}

// TestListCatalog covers the success path (a tenant member sees the curated
// entries) and the error path (no tenant in the context is PermissionDenied).
func TestListCatalog(t *testing.T) {
	s := newConnectorService(t)

	resp, err := s.ListCatalog(tenantCtx("acme"), &tenantv1.ListCatalogRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetEntries())
	ids := map[string]bool{}
	for _, e := range resp.GetEntries() {
		ids[e.GetId()] = true
	}
	assert.True(t, ids["gitlab"], "gitlab must be in the catalog")
	assert.True(t, ids["osv"], "osv must be in the catalog")

	_, err = s.ListCatalog(context.Background(), &tenantv1.ListCatalogRequest{})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// TestEnableConnector covers a successful enable (a ConnectorInstance lands in
// the tenant namespace), the already-enabled path (AlreadyExists), and an
// unknown catalog id (NotFound). The missing-tenant path is PermissionDenied.
func TestEnableConnector(t *testing.T) {
	s := newConnectorService(t)

	resp, err := s.EnableConnector(tenantCtx("acme"), &tenantv1.EnableConnectorRequest{CatalogId: "osv"})
	require.NoError(t, err)
	assert.Equal(t, "osv", resp.GetConnector())

	// The CR must exist in the tenant namespace.
	var ci connectorv1alpha1.ConnectorInstance
	require.NoError(t, s.kube.Get(context.Background(),
		client.ObjectKey{Namespace: "tenant-acme", Name: "osv"}, &ci))
	assert.Equal(t, "osv", ci.Spec.Connector)

	// Enabling the same connector twice is AlreadyExists.
	_, err = s.EnableConnector(tenantCtx("acme"), &tenantv1.EnableConnectorRequest{CatalogId: "osv"})
	assert.Equal(t, codes.AlreadyExists, grpcCode(err))

	// An unknown catalog id is NotFound.
	_, err = s.EnableConnector(tenantCtx("acme"), &tenantv1.EnableConnectorRequest{CatalogId: "does-not-exist"})
	assert.Equal(t, codes.NotFound, grpcCode(err))

	// No tenant in the context is PermissionDenied.
	_, err = s.EnableConnector(context.Background(), &tenantv1.EnableConnectorRequest{CatalogId: "osv"})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// TestListConnectors covers the success path (only the caller's tenant's
// connectors are returned) and the missing-tenant PermissionDenied path.
func TestListConnectors(t *testing.T) {
	acme := connectorcatalogInstance("osv", "tenant-acme")
	other := connectorcatalogInstance("gitlab", "tenant-other")
	s := newConnectorService(t, acme, other)

	resp, err := s.ListConnectors(tenantCtx("acme"), &tenantv1.ListConnectorsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetConnectors(), 1)
	assert.Equal(t, "osv", resp.GetConnectors()[0].GetId())

	_, err = s.ListConnectors(context.Background(), &tenantv1.ListConnectorsRequest{})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// TestDisableConnector covers a successful delete, the not-enabled path
// (NotFound), the empty-connector path (InvalidArgument), and the
// missing-tenant PermissionDenied path.
func TestDisableConnector(t *testing.T) {
	s := newConnectorService(t, connectorcatalogInstance("osv", "tenant-acme"))

	_, err := s.DisableConnector(tenantCtx("acme"),
		&tenantv1.DisableConnectorRequest{Connector: "osv"})
	require.NoError(t, err)

	// The CR must be gone.
	var ci connectorv1alpha1.ConnectorInstance
	getErr := s.kube.Get(context.Background(),
		client.ObjectKey{Namespace: "tenant-acme", Name: "osv"}, &ci)
	require.Error(t, getErr)

	// Disabling a connector that is not enabled is NotFound.
	_, err = s.DisableConnector(tenantCtx("acme"),
		&tenantv1.DisableConnectorRequest{Connector: "osv"})
	assert.Equal(t, codes.NotFound, grpcCode(err))

	// An empty connector name is InvalidArgument.
	_, err = s.DisableConnector(tenantCtx("acme"),
		&tenantv1.DisableConnectorRequest{Connector: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))

	// No tenant in the context is PermissionDenied.
	_, err = s.DisableConnector(context.Background(),
		&tenantv1.DisableConnectorRequest{Connector: "osv"})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// connectorcatalogInstance builds a minimal ConnectorInstance for a fake-client
// seed: the name and namespace are what the service reads back.
func connectorcatalogInstance(name, namespace string) *connectorv1alpha1.ConnectorInstance {
	return &connectorv1alpha1.ConnectorInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: connectorv1alpha1.ConnectorInstanceSpec{
			Connector: name,
			Shape:     connectorv1alpha1.ConnectorShapeHosted,
			Runtime:   connectorv1alpha1.ConnectorRuntimePod,
		},
	}
}

// newFailingConnectorService builds a service whose kube client fails Create,
// List and Delete with a generic error, so the Internal-error branches of each
// RPC are exercised.
func newFailingConnectorService(t *testing.T) *ConnectorService {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, connectorv1alpha1.AddToScheme(scheme))
	kube := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
				return errConnectorBoom
			},
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errConnectorBoom
			},
			Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
				return errConnectorBoom
			},
		}).
		Build()
	return NewConnectorService(kube, &stubCatalogGate{})
}

var errConnectorBoom = errConnectorBoomError("kube is on fire")

type errConnectorBoomError string

func (e errConnectorBoomError) Error() string { return string(e) }

// TestConnectorService_InternalErrors maps an unexpected kube failure to a
// codes.Internal status for each write/read RPC.
func TestConnectorService_InternalErrors(t *testing.T) {
	s := newFailingConnectorService(t)
	ctx := tenantCtx("acme")

	_, err := s.EnableConnector(ctx, &tenantv1.EnableConnectorRequest{CatalogId: "osv"})
	assert.Equal(t, codes.Internal, grpcCode(err))

	_, err = s.ListConnectors(ctx, &tenantv1.ListConnectorsRequest{})
	assert.Equal(t, codes.Internal, grpcCode(err))

	_, err = s.DisableConnector(ctx, &tenantv1.DisableConnectorRequest{Connector: "osv"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

// TestCatalogGate covers the ADR-0067 platform catalog gate: a de-listed
// entry disappears from ListCatalog and is refused by EnableConnector, and a
// gate failure is Internal on both paths (fail closed, never fail open).
func TestCatalogGate(t *testing.T) {
	t.Run("de-listed entry is hidden and refused", func(t *testing.T) {
		gate := &stubCatalogGate{denied: []string{authz.ConnectorComponentObject("gitlab")}}
		s := newConnectorServiceWithGate(t, gate)

		resp, err := s.ListCatalog(tenantCtx("acme"), &tenantv1.ListCatalogRequest{})
		require.NoError(t, err)
		for _, e := range resp.GetEntries() {
			assert.NotEqual(t, "gitlab", e.GetId(), "de-listed entry must be hidden")
		}
		require.NotEmpty(t, resp.GetEntries(), "other entries stay visible")

		_, err = s.EnableConnector(tenantCtx("acme"), &tenantv1.EnableConnectorRequest{CatalogId: "gitlab"})
		assert.Equal(t, codes.NotFound, grpcCode(err))
	})

	t.Run("gate failure is Internal, fail closed", func(t *testing.T) {
		gate := &stubCatalogGate{err: errConnectorBoom}
		s := newConnectorServiceWithGate(t, gate)

		_, err := s.ListCatalog(tenantCtx("acme"), &tenantv1.ListCatalogRequest{})
		assert.Equal(t, codes.Internal, grpcCode(err))

		_, err = s.EnableConnector(tenantCtx("acme"), &tenantv1.EnableConnectorRequest{CatalogId: "osv"})
		assert.Equal(t, codes.Internal, grpcCode(err))
	})
}
