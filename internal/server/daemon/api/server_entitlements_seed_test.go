package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// TestSeedCatalogTenantEnabled_WritesOneTupleForEveryPlatformEnabledItem
// proves the seed is the FGA write, not the response: the response carries
// no count (gibson#502), so the fake authorizer's captured tuples are the
// observable.
func TestSeedCatalogTenantEnabled_WritesOneTupleForEveryPlatformEnabledItem(t *testing.T) {
	az := newFakeAuthorizer().withObjects("system_tenant:_system", "platform_enabled", "component",
		"component:osv-scanner", "nmap", "")
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithAuthorizer(az)

	resp, err := srv.SeedCatalogTenantEnabled(context.Background(), &daemonoperatorv1.SeedCatalogTenantEnabledRequest{TenantId: "acme"})
	require.NoError(t, err)
	require.NotNil(t, resp)

	got := az.writtenTuples()
	require.Len(t, got, 2, "an empty object id is skipped; the bare id is prefixed")
	for _, tup := range got {
		assert.Equal(t, "tenant:acme", tup.User)
		assert.Equal(t, "tenant_enabled", tup.Relation)
	}
	assert.Equal(t, "component:osv-scanner", got[0].Object)
	assert.Equal(t, "component:nmap", got[1].Object)
}

// TestSeedCatalogTenantEnabled_NothingEnabledWritesNothing proves an empty
// platform catalog is a no-op success, not an FGA write of zero tuples.
func TestSeedCatalogTenantEnabled_NothingEnabledWritesNothing(t *testing.T) {
	az := newFakeAuthorizer()
	srv := NewDaemonServer(&mockDaemon{}, nil, nil).WithAuthorizer(az)

	_, err := srv.SeedCatalogTenantEnabled(context.Background(), &daemonoperatorv1.SeedCatalogTenantEnabledRequest{TenantId: "acme"})
	require.NoError(t, err)
	assert.Empty(t, az.writtenTuples())

	_, err = srv.SeedCatalogTenantEnabled(context.Background(), &daemonoperatorv1.SeedCatalogTenantEnabledRequest{})
	require.Error(t, err, "a missing tenant id is refused")
}
