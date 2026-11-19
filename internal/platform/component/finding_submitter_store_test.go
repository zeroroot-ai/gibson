// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
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

// The RPC gives the agent a fixed message for a store failure. The cause, which
// can name the database, stays in the log.
func TestSubmitFinding_AStoreFailureGivesAFixedMessage(t *testing.T) {
	for name, tc := range map[string]struct {
		cause error
		code  codes.Code
	}{
		"connection down": {errors.New("dial tcp 10.0.0.9:5432: connection refused"), codes.Unavailable},
		"not provisioned": {&datapool.NotProvisionedError{Tenant: victimTenant, Reason: "status.dataPlane not ready"},
			codes.FailedPrecondition},
	} {
		t.Run(name, func(t *testing.T) {
			var seen finding.EnhancedFinding
			submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), failingPool{err: tc.cause}, nil, testLogger())
			svc := newWorkIDEnv(t).svc
			svc.findingSubmitter = submitter

			resp, err := svc.SubmitFinding(submitterCtx(victimTenant, "agent_principal:sa-1"),
				&componentpb.SubmitFindingRequest{Finding: []byte(`{"title":"exposed admin panel"}`)})

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Equal(t, tc.code, status.Code(err))
			msg := status.Convert(err).Message()
			assert.NotContains(t, msg, "10.0.0.9")
			assert.NotContains(t, msg, "dataPlane")
			assert.NotContains(t, msg, "finding submitter")
			assert.Empty(t, seen.ID, "the World sink did not run")
		})
	}
}
