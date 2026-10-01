// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
	"github.com/zeroroot-ai/sdk/auth"
)

type fakeSecretResolver struct {
	payload []byte
	err     error
	gotName string
	gotTen  string
}

func (f *fakeSecretResolver) Resolve(ctx context.Context, name string) ([]byte, error) {
	f.gotName = name
	if id, ok := auth.TenantFromContext(ctx); ok {
		f.gotTen = id.String()
	}
	return f.payload, f.err
}

func TestResolveVectorIndex(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")

	t.Run("nil reader is not provisioned", func(t *testing.T) {
		_, err := resolveVectorIndex(context.Background(), nil, tenant)
		var np *datapool.NotProvisionedError
		require.ErrorAs(t, err, &np)
		assert.Equal(t, "acme", np.Tenant)
	})

	t.Run("vault read failure names the path", func(t *testing.T) {
		_, err := resolveVectorIndex(context.Background(), &fakeSecretResolver{err: errors.New("denied")}, tenant)
		var np *datapool.NotProvisionedError
		require.ErrorAs(t, err, &np)
		assert.Contains(t, np.Reason, pdataplane.VaultPathInfraVector)
		assert.Contains(t, np.Reason, "denied")
	})

	t.Run("malformed payload is a fault", func(t *testing.T) {
		_, err := resolveVectorIndex(context.Background(), &fakeSecretResolver{payload: []byte("{not json")}, tenant)
		require.Error(t, err)
		var np *datapool.NotProvisionedError
		assert.NotErrorAs(t, err, &np)
	})

	t.Run("empty index name passes through", func(t *testing.T) {
		got, err := resolveVectorIndex(context.Background(), &fakeSecretResolver{payload: []byte(`{"index_name":""}`)}, tenant)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("happy path reads the infra/vector path as the tenant", func(t *testing.T) {
		f := &fakeSecretResolver{payload: []byte(`{"index_name":"vector_idx:tenant_acme"}`)}
		got, err := resolveVectorIndex(context.Background(), f, tenant)
		require.NoError(t, err)
		assert.Equal(t, "vector_idx:tenant_acme", got)
		assert.Equal(t, pdataplane.VaultPathInfraVector, f.gotName)
		assert.Equal(t, "acme", f.gotTen)
	})
}

// A nil *secrets.Service must reach resolveVectorIndex as a nil interface.
// Otherwise the nil check never fires and Resolve panics on a nil receiver.
func TestDaemonVectorIndexResolver_NilServiceIsNotProvisioned(t *testing.T) {
	d := &daemonImpl{}
	_, err := d.vectorIndexResolver().VectorIndex(context.Background(), auth.MustNewTenantID("acme"))
	var np *datapool.NotProvisionedError
	require.ErrorAs(t, err, &np)
}
