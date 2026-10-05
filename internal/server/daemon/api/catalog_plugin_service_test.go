// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/catalogplugin"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// fakeCatalogPluginStore keeps enabled plugins in memory, keyed by tenant.
type fakeCatalogPluginStore struct {
	rows map[string]map[string]catalogplugin.Plugin
	err  error
}

func newFakeCatalogPluginStore() *fakeCatalogPluginStore {
	return &fakeCatalogPluginStore{rows: map[string]map[string]catalogplugin.Plugin{}}
}

func (f *fakeCatalogPluginStore) Enable(_ context.Context, tenantID, pluginID string) (catalogplugin.Plugin, error) {
	if f.err != nil {
		return catalogplugin.Plugin{}, f.err
	}
	if _, ok := f.rows[tenantID][pluginID]; ok {
		return catalogplugin.Plugin{}, catalogplugin.ErrAlreadyEnabled
	}
	if f.rows[tenantID] == nil {
		f.rows[tenantID] = map[string]catalogplugin.Plugin{}
	}
	p := catalogplugin.Plugin{TenantID: tenantID, PluginID: pluginID, Phase: catalogplugin.PhasePending}
	f.rows[tenantID][pluginID] = p
	return p, nil
}

func (f *fakeCatalogPluginStore) Disable(_ context.Context, tenantID, pluginID string) error {
	if f.err != nil {
		return f.err
	}
	if _, ok := f.rows[tenantID][pluginID]; !ok {
		return catalogplugin.ErrNotEnabled
	}
	delete(f.rows[tenantID], pluginID)
	return nil
}

func (f *fakeCatalogPluginStore) List(_ context.Context, tenantID string) ([]catalogplugin.Plugin, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []catalogplugin.Plugin
	for _, p := range f.rows[tenantID] {
		out = append(out, p)
	}
	return out, nil
}

// pluginGate is a catalog gate with a fixed set of offered objects.
type pluginGate struct {
	offered map[string]bool
	err     error
}

func (g pluginGate) Check(_ context.Context, _, _, object string) (bool, error) {
	return g.offered[object], g.err
}

func (g pluginGate) BatchCheck(_ context.Context, checks []authz.CheckRequest) ([]bool, error) {
	if g.err != nil {
		return nil, g.err
	}
	out := make([]bool, len(checks))
	for i, c := range checks {
		out[i] = g.offered[c.Object]
	}
	return out, nil
}

func githubOffered() pluginGate {
	return pluginGate{offered: map[string]bool{authz.ComponentObject(authz.KindPlugin, "github"): true}}
}

func pluginTenantCtx(t *testing.T, tenant string) context.Context {
	t.Helper()
	return auth.ContextWithTenantString(context.Background(), tenant)
}

func TestEnableCatalogPlugin_EnableListDisable(t *testing.T) {
	store := newFakeCatalogPluginStore()
	svc := NewCatalogPluginService(store, githubOffered())
	acme := pluginTenantCtx(t, "acme")

	cat, err := svc.ListPluginCatalog(acme, &tenantv1.ListPluginCatalogRequest{})
	require.NoError(t, err)
	require.Len(t, cat.GetEntries(), 1)
	assert.Equal(t, "github", cat.GetEntries()[0].GetId())
	assert.NotEmpty(t, cat.GetEntries()[0].GetDisplayName())

	enabled, err := svc.EnableCatalogPlugin(acme, &tenantv1.EnableCatalogPluginRequest{PluginId: "github"})
	require.NoError(t, err)
	assert.Equal(t, "github", enabled.GetPlugin().GetId())
	assert.Equal(t, catalogplugin.PhasePending, enabled.GetPlugin().GetPhase())

	_, err = svc.EnableCatalogPlugin(acme, &tenantv1.EnableCatalogPluginRequest{PluginId: "github"})
	assert.Equal(t, codes.AlreadyExists, status_grpc.Code(err))

	list, err := svc.ListCatalogPlugins(acme, &tenantv1.ListCatalogPluginsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetPlugins(), 1)

	// Another tenant sees nothing of acme's.
	other, err := svc.ListCatalogPlugins(pluginTenantCtx(t, "globex"), &tenantv1.ListCatalogPluginsRequest{})
	require.NoError(t, err)
	assert.Empty(t, other.GetPlugins())

	_, err = svc.DisableCatalogPlugin(acme, &tenantv1.DisableCatalogPluginRequest{PluginId: "github"})
	require.NoError(t, err)
	_, err = svc.DisableCatalogPlugin(acme, &tenantv1.DisableCatalogPluginRequest{PluginId: "github"})
	assert.Equal(t, codes.NotFound, status_grpc.Code(err))
}

// A plugin the catalog does not list, and a plugin the gate does not pass,
// both read as not in the catalog, and nothing reaches the store.
func TestEnableCatalogPlugin_RefusesWhatTheCatalogDoesNotOffer(t *testing.T) {
	store := newFakeCatalogPluginStore()
	acme := pluginTenantCtx(t, "acme")

	svc := NewCatalogPluginService(store, githubOffered())
	_, err := svc.EnableCatalogPlugin(acme, &tenantv1.EnableCatalogPluginRequest{PluginId: "not-a-plugin"})
	assert.Equal(t, codes.NotFound, status_grpc.Code(err))

	delisted := NewCatalogPluginService(store, pluginGate{})
	_, err = delisted.EnableCatalogPlugin(acme, &tenantv1.EnableCatalogPluginRequest{PluginId: "github"})
	assert.Equal(t, codes.NotFound, status_grpc.Code(err))
	cat, err := delisted.ListPluginCatalog(acme, &tenantv1.ListPluginCatalogRequest{})
	require.NoError(t, err)
	assert.Empty(t, cat.GetEntries())

	assert.Empty(t, store.rows)
}

// failingPluginServices returns a service with no failure, one whose catalog
// gate fails, and one whose store fails.
func failingPluginServices() (ok, gateDown, dbDown *CatalogPluginService) {
	storeDown := newFakeCatalogPluginStore()
	storeDown.err = errors.New("db down")
	return NewCatalogPluginService(newFakeCatalogPluginStore(), githubOffered()),
		NewCatalogPluginService(newFakeCatalogPluginStore(), pluginGate{err: errors.New("fga down")}),
		NewCatalogPluginService(storeDown, githubOffered())
}

// Each RPC needs a tenant, and a gate or store error fails closed.

func TestListPluginCatalog_FailsClosed(t *testing.T) {
	ok, gateDown, _ := failingPluginServices()
	_, err := ok.ListPluginCatalog(context.Background(), &tenantv1.ListPluginCatalogRequest{})
	assert.Equal(t, codes.PermissionDenied, status_grpc.Code(err))
	_, err = gateDown.ListPluginCatalog(pluginTenantCtx(t, "acme"), &tenantv1.ListPluginCatalogRequest{})
	assert.Equal(t, codes.Internal, status_grpc.Code(err))
}

func TestEnableCatalogPlugin_FailsClosed(t *testing.T) {
	ok, gateDown, dbDown := failingPluginServices()
	req := &tenantv1.EnableCatalogPluginRequest{PluginId: "github"}
	_, err := ok.EnableCatalogPlugin(context.Background(), req)
	assert.Equal(t, codes.PermissionDenied, status_grpc.Code(err))
	_, err = gateDown.EnableCatalogPlugin(pluginTenantCtx(t, "acme"), req)
	assert.Equal(t, codes.Internal, status_grpc.Code(err))
	_, err = dbDown.EnableCatalogPlugin(pluginTenantCtx(t, "acme"), req)
	assert.Equal(t, codes.Internal, status_grpc.Code(err))
}

func TestListCatalogPlugins_FailsClosed(t *testing.T) {
	ok, _, dbDown := failingPluginServices()
	_, err := ok.ListCatalogPlugins(context.Background(), &tenantv1.ListCatalogPluginsRequest{})
	assert.Equal(t, codes.PermissionDenied, status_grpc.Code(err))
	_, err = dbDown.ListCatalogPlugins(pluginTenantCtx(t, "acme"), &tenantv1.ListCatalogPluginsRequest{})
	assert.Equal(t, codes.Internal, status_grpc.Code(err))
}

func TestDisableCatalogPlugin_FailsClosed(t *testing.T) {
	ok, _, dbDown := failingPluginServices()
	req := &tenantv1.DisableCatalogPluginRequest{PluginId: "github"}
	_, err := ok.DisableCatalogPlugin(context.Background(), req)
	assert.Equal(t, codes.PermissionDenied, status_grpc.Code(err))
	_, err = ok.DisableCatalogPlugin(pluginTenantCtx(t, "acme"), &tenantv1.DisableCatalogPluginRequest{})
	assert.Equal(t, codes.InvalidArgument, status_grpc.Code(err))
	_, err = dbDown.DisableCatalogPlugin(pluginTenantCtx(t, "acme"), req)
	assert.Equal(t, codes.Internal, status_grpc.Code(err))
}
