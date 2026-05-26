package datapool

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/datapool/vectordb"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeVectorDriver is a test double for vectordb.Driver.
type fakeVectorDriver struct {
	// existing is the set of collections that "exist" in the fake store.
	existing map[string]bool
	// closed tracks whether Close was called.
	closed bool
}

func (f *fakeVectorDriver) For(_ context.Context, collection string) (vectordb.Client, error) {
	if !f.existing[collection] {
		return nil, errors.New("collection not found: " + collection)
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

func TestVectorPerTenant_ForTenant_HappyPath(t *testing.T) {
	driver := &fakeVectorDriver{
		existing: map[string]bool{
			"tenant_acme": true,
		},
	}
	v := newVectorPerTenant(driver)

	tenant := auth.MustNewTenantID("acme")
	client, err := v.ForTenant(context.Background(), tenant)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.IsType(t, &fakeVectorClient{}, client)
}

func TestVectorPerTenant_ForTenant_NotProvisioned(t *testing.T) {
	driver := &fakeVectorDriver{
		existing: map[string]bool{},
	}
	v := newVectorPerTenant(driver)

	tenant := auth.MustNewTenantID("unknown")
	_, err := v.ForTenant(context.Background(), tenant)
	require.Error(t, err)

	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Equal(t, "unknown", npErr.Tenant)
}

func TestVectorPerTenant_ForTenant_HyphenTenant(t *testing.T) {
	// Tenant IDs with hyphens should map to underscore collection names.
	driver := &fakeVectorDriver{
		existing: map[string]bool{
			"tenant_my_corp": true,
		},
	}
	v := newVectorPerTenant(driver)

	tenant := auth.MustNewTenantID("my-corp")
	client, err := v.ForTenant(context.Background(), tenant)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestVectorPerTenant_Close(t *testing.T) {
	driver := &fakeVectorDriver{existing: map[string]bool{}}
	v := newVectorPerTenant(driver)

	err := v.Close()
	require.NoError(t, err)
	assert.True(t, driver.closed)
}

func TestSanitizeForVector_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"acme", "acme"},
		{"my-corp", "my_corp"},
		{"abc123", "abc123"},
		{"a-b-c", "a_b_c"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := sanitizeForVector(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestSanitizeForVector_Rejects(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"uppercase", "ACME"},
		{"dot", "my.tenant"},
		{"slash", "ten/ant"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sanitizeForVector(tc.input)
			require.Error(t, err)
		})
	}
}
