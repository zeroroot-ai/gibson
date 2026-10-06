// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantconnector"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
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

// memConnectorStore is an in-memory ConnectorStore with the semantics of
// tenantconnector.Store. err fails every call.
type memConnectorStore struct {
	rows []tenantconnector.Connector
	err  error
}

func (m *memConnectorStore) find(tenant, connector string) int {
	for i, r := range m.rows {
		if r.TenantID == tenant && r.ConnectorID == connector {
			return i
		}
	}
	return -1
}

func (m *memConnectorStore) Enable(_ context.Context, tenant, connector string) (tenantconnector.Connector, error) {
	if m.err != nil {
		return tenantconnector.Connector{}, m.err
	}
	if m.find(tenant, connector) >= 0 {
		return tenantconnector.Connector{}, tenantconnector.ErrAlreadyEnabled
	}
	c := tenantconnector.Connector{TenantID: tenant, ConnectorID: connector, Phase: tenantconnector.PhasePending}
	m.rows = append(m.rows, c)
	return c, nil
}

func (m *memConnectorStore) Disable(_ context.Context, tenant, connector string) error {
	if m.err != nil {
		return m.err
	}
	i := m.find(tenant, connector)
	if i < 0 {
		return tenantconnector.ErrNotEnabled
	}
	m.rows = append(m.rows[:i], m.rows[i+1:]...)
	return nil
}

func (m *memConnectorStore) List(_ context.Context, tenant string) ([]tenantconnector.Connector, error) {
	if m.err != nil {
		return nil, m.err
	}
	var out []tenantconnector.Connector
	for _, r := range m.rows {
		if r.TenantID == tenant {
			out = append(out, r)
		}
	}
	return out, nil
}

// newConnectorService builds a ConnectorService over an in-memory store
// seeded with the given rows and an allow-all catalog gate.
func newConnectorService(t *testing.T, seed ...tenantconnector.Connector) (*ConnectorService, *memConnectorStore) {
	t.Helper()
	return newConnectorServiceWithGate(t, &stubCatalogGate{}, seed...)
}

func newConnectorServiceWithGate(
	t *testing.T, gate CatalogGate, seed ...tenantconnector.Connector,
) (*ConnectorService, *memConnectorStore) {
	t.Helper()
	store := &memConnectorStore{rows: seed}
	return NewConnectorService(store, gate), store
}

// TestListCatalog covers the success path (a tenant member sees the curated
// entries) and the error path (no tenant in the context is PermissionDenied).
func TestListCatalog(t *testing.T) {
	s, _ := newConnectorService(t)

	resp, err := s.ListCatalog(tenantCtx("acme"), &tenantv1.ListCatalogRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetEntries())
	ids := map[string]bool{}
	for _, e := range resp.GetEntries() {
		ids[e.GetId()] = true
	}
	assert.True(t, ids["gitlab"], "gitlab must be in the catalog")
	assert.True(t, ids["github"], "github must be in the catalog")
	assert.False(t, ids["osv"], "the OSV prototype left the catalog (gibson#750)")

	_, err = s.ListCatalog(context.Background(), &tenantv1.ListCatalogRequest{})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// TestEnableConnector covers a successful enable (a row for the tenant is in
// the store, and nothing else), the already-enabled path (AlreadyExists), and
// an unknown catalog id (NotFound). The missing-tenant path is
// PermissionDenied.
func TestEnableConnector(t *testing.T) {
	s, store := newConnectorService(t)

	resp, err := s.EnableConnector(tenantCtx("acme"), &tenantv1.EnableConnectorRequest{CatalogId: "gitlab"})
	require.NoError(t, err)
	assert.Equal(t, "gitlab", resp.GetConnector())
	assert.Equal(t, "Pending", resp.GetPhase())
	assert.Equal(t, []tenantconnector.Connector{
		{TenantID: "acme", ConnectorID: "gitlab", Phase: tenantconnector.PhasePending},
	}, store.rows)

	// Enabling the same connector twice is AlreadyExists.
	_, err = s.EnableConnector(tenantCtx("acme"), &tenantv1.EnableConnectorRequest{CatalogId: "gitlab"})
	assert.Equal(t, codes.AlreadyExists, grpcCode(err))

	// An unknown catalog id is NotFound.
	_, err = s.EnableConnector(tenantCtx("acme"), &tenantv1.EnableConnectorRequest{CatalogId: "does-not-exist"})
	assert.Equal(t, codes.NotFound, grpcCode(err))

	// No tenant in the context is PermissionDenied.
	_, err = s.EnableConnector(context.Background(), &tenantv1.EnableConnectorRequest{CatalogId: "gitlab"})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// TestListConnectors covers the success path (only the caller's tenant's
// connectors are returned, with the state the operator reported and the shape
// of the catalog entry) and the missing-tenant PermissionDenied path.
func TestListConnectors(t *testing.T) {
	s, _ := newConnectorService(t,
		tenantconnector.Connector{TenantID: "acme", ConnectorID: "gitlab", Phase: "Ready", DiscoveredTools: 9},
		tenantconnector.Connector{TenantID: "other", ConnectorID: "hosted-fixture", Phase: "Pending"},
	)

	resp, err := s.ListConnectors(tenantCtx("acme"), &tenantv1.ListConnectorsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetConnectors(), 1)
	got := resp.GetConnectors()[0]
	assert.Equal(t, "gitlab", got.GetId())
	assert.Equal(t, "Ready", got.GetPhase())
	assert.Equal(t, int32(9), got.GetDiscoveredTools())
	assert.Equal(t, "Remote", got.GetShape())
	assert.Equal(t, "pod", got.GetRuntime())

	_, err = s.ListConnectors(context.Background(), &tenantv1.ListConnectorsRequest{})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// TestDisableConnector covers a successful delete, the not-enabled path
// (NotFound), the empty-connector path (InvalidArgument), and the
// missing-tenant PermissionDenied path.
func TestDisableConnector(t *testing.T) {
	s, store := newConnectorService(t, tenantconnector.Connector{TenantID: "acme", ConnectorID: "hosted-fixture"})

	_, err := s.DisableConnector(tenantCtx("acme"),
		&tenantv1.DisableConnectorRequest{Connector: "hosted-fixture"})
	require.NoError(t, err)
	assert.Empty(t, store.rows, "the row must be gone")

	// Disabling a connector that is not enabled is NotFound.
	_, err = s.DisableConnector(tenantCtx("acme"),
		&tenantv1.DisableConnectorRequest{Connector: "hosted-fixture"})
	assert.Equal(t, codes.NotFound, grpcCode(err))

	// An empty connector name is InvalidArgument.
	_, err = s.DisableConnector(tenantCtx("acme"),
		&tenantv1.DisableConnectorRequest{Connector: ""})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))

	// No tenant in the context is PermissionDenied.
	_, err = s.DisableConnector(context.Background(),
		&tenantv1.DisableConnectorRequest{Connector: "hosted-fixture"})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

var errConnectorBoom = errors.New("the database is on fire")

// TestConnectorService_InternalErrors maps an unexpected store failure to a
// codes.Internal status for each write/read RPC.
func TestConnectorService_InternalErrors(t *testing.T) {
	s, store := newConnectorService(t)
	store.err = errConnectorBoom
	ctx := tenantCtx("acme")

	_, err := s.EnableConnector(ctx, &tenantv1.EnableConnectorRequest{CatalogId: "gitlab"})
	assert.Equal(t, codes.Internal, grpcCode(err))

	_, err = s.ListConnectors(ctx, &tenantv1.ListConnectorsRequest{})
	assert.Equal(t, codes.Internal, grpcCode(err))

	_, err = s.DisableConnector(ctx, &tenantv1.DisableConnectorRequest{Connector: "hosted-fixture"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

// TestCatalogGate covers the ADR-0067 platform catalog gate: a de-listed
// entry disappears from ListCatalog and is refused by EnableConnector, and a
// gate failure is Internal on both paths (fail closed, never fail open).
func TestCatalogGate(t *testing.T) {
	t.Run("de-listed entry is hidden and refused", func(t *testing.T) {
		gate := &stubCatalogGate{denied: []string{authz.ConnectorComponentObject("gitlab")}}
		s, _ := newConnectorServiceWithGate(t, gate)

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
		s, _ := newConnectorServiceWithGate(t, gate)

		_, err := s.ListCatalog(tenantCtx("acme"), &tenantv1.ListCatalogRequest{})
		assert.Equal(t, codes.Internal, grpcCode(err))

		_, err = s.EnableConnector(tenantCtx("acme"), &tenantv1.EnableConnectorRequest{CatalogId: "gitlab"})
		assert.Equal(t, codes.Internal, grpcCode(err))
	})
}
