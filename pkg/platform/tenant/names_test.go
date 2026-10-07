// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenant_test

import (
	"testing"

	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/pkg/platform/tenant"
)

func TestNames_TenantIDRoundTrip(t *testing.T) {
	id := auth.MustNewTenantID("zeroroot-ai")
	n := tenant.FromTenantID(id)
	if !n.TenantID().Equal(id) {
		t.Errorf("TenantID() round-trip failed: got %v, want %v", n.TenantID(), id)
	}
}

// TestNames_RedisIndexField_NotHashKey is a guard against the historical
// bug where some callers used "tenant_db_index" or "tenant:index" as the
// _field_ name. The field is the bare slug; the hash key constant lives
// in pkg/platform/dataplane.
func TestNames_RedisIndexField_NotHashKey(t *testing.T) {
	id := auth.MustNewTenantID("acme")
	field := tenant.FromTenantID(id).RedisIndexField()
	for _, forbidden := range []string{"tenant:index", "tenant_db_index"} {
		if field == forbidden {
			t.Errorf("RedisIndexField() returned the master-index hash key %q; field should be the tenant slug", forbidden)
		}
	}
}
