// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// failingPool is a pool whose tenant connection always fails.
type failingPool struct {
	datapool.Pool
	err error
}

func (p failingPool) For(context.Context, auth.TenantID) (*datapool.Conn, error) { return nil, p.err }

// Postgres is the one home of the fields and the evidence of a finding. A
// failed write fails the submit, and the World never hears of the finding.
func TestFindingSubmitter_AStoreFailureFailsTheSubmitBeforeTheWorld(t *testing.T) {
	for name, cause := range map[string]error{
		"connection down": errors.New("postgres down"),
		"not provisioned": &datapool.NotProvisionedError{Tenant: victimTenant},
	} {
		t.Run(name, func(t *testing.T) {
			var seen finding.EnhancedFinding
			submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), failingPool{err: cause}, nil, testLogger())

			id, err := submitter.Submit(submitterCtx(victimTenant, "agent_principal:sa-1"),
				victimTenant, "", `{"title":"exposed admin panel","severity":"info"}`, "", "")

			require.Error(t, err)
			require.ErrorIs(t, err, cause)
			assert.Empty(t, id, "no id for a finding that was not stored")
			assert.Empty(t, seen.ID, "the World sink did not run")
		})
	}
}
