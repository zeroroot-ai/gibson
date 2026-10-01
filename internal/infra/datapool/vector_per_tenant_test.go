// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool/vectordb"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeVectorDriver is a test double for vectordb.Driver.
type fakeVectorDriver struct {
	// existing is the set of index names that "exist" in the fake store.
	existing map[string]bool
	// asked records every index name For was called with, in order. The
	// regression tests read it, because the name the driver receives is the
	// whole defect in gibson#468.
	asked []string
	// closed tracks whether Close was called.
	closed bool
	// failWith, when set, is returned by For instead of consulting existing.
	// It is how a fault that is NOT "index does not exist" is exercised.
	failWith error
}

func (f *fakeVectorDriver) For(_ context.Context, collection string) (vectordb.Client, error) {
	f.asked = append(f.asked, collection)
	if f.failWith != nil {
		return nil, f.failWith
	}
	if !f.existing[collection] {
		return nil, errors.New("index not found: " + collection)
	}
	return &fakeVectorClient{collection: collection}, nil
}

func (f *fakeVectorDriver) Close() error {
	f.closed = true
	return nil
}

// fakeVectorClient is a test double for vectordb.Client.
type fakeVectorClient struct {
	collection string
}

func (c *fakeVectorClient) Upsert(_ context.Context, _ []vectordb.Point) error { return nil }
func (c *fakeVectorClient) Delete(_ context.Context, _ []string) error         { return nil }
func (c *fakeVectorClient) Search(_ context.Context, _ []float32, _ uint64, _ *vectordb.Filter) ([]vectordb.SearchResult, error) {
	return nil, nil
}

// staticIndex resolves every tenant to one name.
func staticIndex(name string) VectorIndexResolver {
	return VectorIndexResolverFunc(func(_ context.Context, _ auth.TenantID) (string, error) {
		return name, nil
	})
}

func TestVectorPerTenant_ForTenant_HappyPath(t *testing.T) {
	driver := &fakeVectorDriver{
		existing: map[string]bool{"vector_idx:tenant_acme": true},
	}
	v := newVectorPerTenant(driver, staticIndex("vector_idx:tenant_acme"))

	client, err := v.ForTenant(context.Background(), auth.MustNewTenantID("acme"))
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.IsType(t, &fakeVectorClient{}, client)
}

// TestVectorPerTenant_ForTenant_AsksForTheResolvedIndex is the gibson#468
// regression. The tenant-operator creates `vector_idx:tenant_<db>` and records
// that name in Vault. This package used to derive `tenant_<db>` instead and ask
// the driver for it, so FT.INFO missed, and the miss was reported as an
// unprovisioned tenant. The name the driver sees must be the resolved name,
// byte for byte.
func TestVectorPerTenant_ForTenant_AsksForTheResolvedIndex(t *testing.T) {
	const index = "vector_idx:tenant_acme"
	driver := &fakeVectorDriver{existing: map[string]bool{index: true}}
	v := newVectorPerTenant(driver, staticIndex(index))

	_, err := v.ForTenant(context.Background(), auth.MustNewTenantID("acme"))
	require.NoError(t, err)

	require.Len(t, driver.asked, 1)
	assert.Equal(t, index, driver.asked[0])
	assert.NotEqual(t, "tenant_acme", driver.asked[0], "the derived name is the defect")
}

func TestVectorPerTenant_ForTenant_IndexMissingInStore(t *testing.T) {
	driver := &fakeVectorDriver{existing: map[string]bool{}}
	v := newVectorPerTenant(driver, staticIndex("vector_idx:tenant_unknown"))

	_, err := v.ForTenant(context.Background(), auth.MustNewTenantID("unknown"))
	require.Error(t, err)

	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Equal(t, "unknown", npErr.Tenant)
}

// An empty name is how Vault reports a tenant whose vector step never ran.
func TestVectorPerTenant_ForTenant_NoIndexRecorded(t *testing.T) {
	driver := &fakeVectorDriver{existing: map[string]bool{}}
	v := newVectorPerTenant(driver, staticIndex(""))

	_, err := v.ForTenant(context.Background(), auth.MustNewTenantID("acme"))
	require.Error(t, err)

	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Equal(t, "acme", npErr.Tenant)
	assert.Contains(t, npErr.Reason, "no vector index recorded")
	assert.Empty(t, driver.asked, "a tenant with no index must not reach the store")
}

// A NotProvisionedError from the resolver passes through unchanged, so the
// caller can tell "this tenant has no vector store" from "the resolver broke".
func TestVectorPerTenant_ForTenant_ResolverNotProvisionedPassesThrough(t *testing.T) {
	driver := &fakeVectorDriver{existing: map[string]bool{}}
	v := newVectorPerTenant(driver, VectorIndexResolverFunc(func(_ context.Context, tenant auth.TenantID) (string, error) {
		return "", &NotProvisionedError{Tenant: tenant.String(), Reason: "vault read failed"}
	}))

	_, err := v.ForTenant(context.Background(), auth.MustNewTenantID("acme"))
	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Equal(t, "vault read failed", npErr.Reason)
}

func TestVectorPerTenant_ForTenant_ResolverError(t *testing.T) {
	driver := &fakeVectorDriver{existing: map[string]bool{}}
	boom := errors.New("boom")
	v := newVectorPerTenant(driver, VectorIndexResolverFunc(func(_ context.Context, _ auth.TenantID) (string, error) {
		return "", boom
	}))

	_, err := v.ForTenant(context.Background(), auth.MustNewTenantID("acme"))
	require.ErrorIs(t, err, boom)

	var npErr *NotProvisionedError
	assert.NotErrorAs(t, err, &npErr, "a broken resolver is not an unprovisioned tenant")
}

func TestVectorPerTenant_Close(t *testing.T) {
	driver := &fakeVectorDriver{existing: map[string]bool{}}
	v := newVectorPerTenant(driver, staticIndex("vector_idx:tenant_acme"))

	require.NoError(t, v.Close())
	assert.True(t, driver.closed)
}

// TestValidateVectorConfig covers the half-configured cases. An address with no
// resolver was the shipped state: the pool built a driver and no Conn ever got
// a handle, so every vector-backed read refused for every tenant.
func TestValidateVectorConfig(t *testing.T) {
	resolver := staticIndex("vector_idx:tenant_acme")

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "neither set", cfg: Config{}},
		{name: "both set", cfg: Config{VectorStoreAddr: "redis:6379", VectorIndexResolver: resolver}},
		{name: "addr without resolver", cfg: Config{VectorStoreAddr: "redis:6379"}, wantErr: true},
		{name: "resolver without addr", cfg: Config{VectorIndexResolver: resolver}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateVectorConfig(tc.cfg)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "must be set together")
				return
			}
			require.NoError(t, err)
		})
	}
}

type fakeVectorSource struct {
	client vectordb.Client
	err    error
}

func (f fakeVectorSource) ForTenant(context.Context, auth.TenantID) (vectordb.Client, error) {
	return f.client, f.err
}

func TestAttachVector(t *testing.T) {
	tenant := auth.MustNewTenantID("acme")

	t.Run("not provisioned leaves Vector nil and does not fail", func(t *testing.T) {
		conn := &Conn{Tenant: tenant}
		err := attachVector(context.Background(), fakeVectorSource{err: &NotProvisionedError{Tenant: "acme", Reason: "x"}}, conn)
		require.NoError(t, err)
		assert.Nil(t, conn.Vector)
	})

	t.Run("wrapped not provisioned is still tolerated", func(t *testing.T) {
		conn := &Conn{Tenant: tenant}
		wrapped := fmt.Errorf("wrap: %w", &NotProvisionedError{Tenant: "acme", Reason: "x"})
		require.NoError(t, attachVector(context.Background(), fakeVectorSource{err: wrapped}, conn))
		assert.Nil(t, conn.Vector)
	})

	t.Run("any other error fails the acquisition", func(t *testing.T) {
		boom := errors.New("boom")
		conn := &Conn{Tenant: tenant}
		err := attachVector(context.Background(), fakeVectorSource{err: boom}, conn)
		require.ErrorIs(t, err, boom)
		assert.Nil(t, conn.Vector)
	})

	t.Run("success assigns the client", func(t *testing.T) {
		c := &fakeVectorClient{}
		conn := &Conn{Tenant: tenant}
		require.NoError(t, attachVector(context.Background(), fakeVectorSource{client: c}, conn))
		assert.Same(t, c, conn.Vector)
	})
}

// A driver fault that is NOT "index does not exist" is a real error and must
// NOT be reported as NotProvisioned: a tenant whose Redis is unreachable has not
// lost its provisioning, and treating the two alike would leave Conn.Vector nil
// and the readers reporting the tenant unprovisioned for the life of the outage.
func TestVectorPerTenant_ForTenant_DriverFaultIsNotNotProvisioned(t *testing.T) {
	driver := &fakeVectorDriver{failWith: errors.New("dial tcp 10.0.0.1:6379: connect: connection refused")}
	v := newVectorPerTenant(driver, staticIndex("vector_idx:tenant_acme"))

	_, err := v.ForTenant(context.Background(), auth.MustNewTenantID("acme"))
	if err == nil {
		t.Fatal("want an error when the driver cannot be reached")
	}
	var np *NotProvisionedError
	if errors.As(err, &np) {
		t.Errorf("a connection fault was reported as NotProvisioned: %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %v, want the driver fault to survive wrapping", err)
	}
	if !strings.Contains(err.Error(), "vector_idx:tenant_acme") {
		t.Errorf("error = %v, want it to name the index it tried", err)
	}
}
