// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
)

// writeWorkContext writes a work-item context hash into miniredis using the
// same key format as RegisterWorkContext, allowing tests to set up mappings
// directly.
func writeWorkContext(t *testing.T, mr *miniredis.Miniredis, workID, missionID, tenantID string) {
	t.Helper()

	key := workContextKey(workID)
	mr.HSet(key, workContextMissionField, missionID)
	mr.HSet(key, workContextTenantField, tenantID)
	mr.SetTTL(key, workContextTTL)
}
