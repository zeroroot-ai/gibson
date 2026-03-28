package testing

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zero-day-ai/gibson/internal/auth"
)

func TestWithTestTenant(t *testing.T) {
	ctx := WithTestTenant()

	tenant := auth.TenantFromContext(ctx)
	assert.Equal(t, DefaultTestTenant, tenant)
}

func TestWithTenant(t *testing.T) {
	customTenant := "custom-tenant-123"
	ctx := WithTenant(context.Background(), customTenant)

	tenant := auth.TenantFromContext(ctx)
	assert.Equal(t, customTenant, tenant)
}

func TestWithTestTenantCancel(t *testing.T) {
	ctx, cancel := WithTestTenantCancel()
	defer cancel()

	// Verify tenant is set
	tenant := auth.TenantFromContext(ctx)
	assert.Equal(t, DefaultTestTenant, tenant)

	// Verify context can be canceled
	cancel()
	assert.Error(t, ctx.Err())
}

func TestMultipleTenantContexts(t *testing.T) {
	// Test that different contexts have different tenants
	ctx1 := WithTenant(context.Background(), "tenant-1")
	ctx2 := WithTenant(context.Background(), "tenant-2")

	tenant1 := auth.TenantFromContext(ctx1)
	tenant2 := auth.TenantFromContext(ctx2)

	assert.Equal(t, "tenant-1", tenant1)
	assert.Equal(t, "tenant-2", tenant2)
	assert.NotEqual(t, tenant1, tenant2)
}
