// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A store whose Redis is gone returns an error from Disable. It does not
// report a removal that did not happen.
func TestComponentAccessStore_Disable_RedisDown_ReturnsError(t *testing.T) {
	store, mr := newTestComponentAccessStore(t)
	mr.Close()

	err := store.Disable(context.Background(), "tenant-a", "gitlab")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disable component")
}

// A store whose Redis is gone returns an error from ListTenantAccess. It does
// not return an empty list as if the tenant had no access records.
func TestComponentAccessStore_ListTenantAccess_RedisDown_ReturnsError(t *testing.T) {
	store, mr := newTestComponentAccessStore(t)
	mr.Close()

	records, err := store.ListTenantAccess(context.Background(), "tenant-a")
	require.Error(t, err)
	assert.Nil(t, records)
}

func accessServer(store ComponentAccessStore) *ComponentServiceServer {
	srv := boundedComponentServer(nil)
	srv.componentAccess = store
	return srv
}

// ListTenantPlugins returns each access record of the tenant with its
// component name.
func TestListTenantPlugins_ReturnsTheRecordsOfTheTenant(t *testing.T) {
	store, _ := newTestComponentAccessStore(t)
	ctx := auth.ContextWithTenantString(context.Background(), "tenant-a")
	require.NoError(t, store.Enable(ctx, "tenant-a", "gitlab", nil, "admin"))

	resp, err := accessServer(store).ListTenantPlugins(ctx, &componentpb.ListTenantPluginsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetPlugins(), 1)
	assert.Equal(t, "gitlab", resp.GetPlugins()[0].GetPluginName())
	assert.Equal(t, "tenant-a", resp.GetPlugins()[0].GetTenantId())
}

// ListTenantPlugins maps a store failure to codes.Internal.
func TestListTenantPlugins_StoreFailure_ReturnsInternal(t *testing.T) {
	store, mr := newTestComponentAccessStore(t)
	mr.Close()
	ctx := auth.ContextWithTenantString(context.Background(), "tenant-a")

	_, err := accessServer(store).ListTenantPlugins(ctx, &componentpb.ListTenantPluginsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}
