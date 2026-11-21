// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/finding/pgstore"
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

// poolStore is the store that the daemon builds: pgstore over a data pool.
func poolStore(p datapool.Pool) FindingRecordStore {
	return pgstore.New(func() datapool.Pool { return p })
}

// memFindingStore is a finding store that keeps each record in memory. err,
// when set, fails each write.
type memFindingStore struct {
	mu      sync.Mutex
	records []finding.EnhancedFinding
	err     error
}

func (m *memFindingStore) Store(_ context.Context, _ string, f finding.EnhancedFinding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.records = append(m.records, f)
	return nil
}

// A daemon with no data pool refuses each finding. The World never gets a
// finding that has no store row.
func TestFindingSubmitter_NoDataPoolRefusesTheSubmit(t *testing.T) {
	var seen finding.EnhancedFinding
	submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), poolStore(nil), nil, testLogger())

	id, err := submitter.Submit(submitterCtx(victimTenant, "agent_principal:sa-1"),
		victimTenant, "", `{"title":"exposed admin panel"}`, "", "", "")

	require.ErrorIs(t, err, ErrFindingNotStored)
	assert.Empty(t, id)
	assert.Empty(t, seen.ID, "the World sink did not run")
}

// A stored finding is the record that the World gets.
func TestFindingSubmitter_TheWorldGetsTheStoredRecord(t *testing.T) {
	var seen finding.EnhancedFinding
	store := &memFindingStore{}
	submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), store, nil, testLogger())

	id, err := submitter.Submit(submitterCtx(victimTenant, "agent_principal:sa-1"),
		victimTenant, "", `{"title":"exposed admin panel"}`, "", "", "")

	require.NoError(t, err)
	require.Len(t, store.records, 1)
	assert.Equal(t, id, store.records[0].ID.String())
	assert.Equal(t, id, seen.ID.String())
}

// A submit with an idempotency key gets the id of the verified submitter and
// the key, so a second read of one result names the same finding. Another
// submitter with the same key gets another id (review R6).
func TestFindingSubmitter_AnIdempotencyKeyNamesTheFinding(t *testing.T) {
	var seen finding.EnhancedFinding
	store := &memFindingStore{}
	submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), store, nil, testLogger())
	submit := func(principal string) string {
		id, err := submitter.Submit(submitterCtx(victimTenant, principal),
			victimTenant, "", `{"title":"exposed admin panel"}`, "", "", "qualys:host-9:qid-1")
		require.NoError(t, err)
		return id
	}
	first, second := submit("agent_principal:sa-1"), submit("agent_principal:sa-1")
	assert.Equal(t, first, second)
	assert.Equal(t, finding.ResultID(victimTenant, "agent_principal:sa-1", "qualys:host-9:qid-1").String(), first)
	assert.NotEqual(t, first, submit("agent_principal:sa-2"))

	// A subject with no typed prefix keeps its raw form in the id, as on the
	// harness path, and not the "user:" form of the FGA principal.
	raw, err := submitter.Submit(submitterCtx(victimTenant, "spiffe://zeroroot.ai/agent/x"),
		victimTenant, "", `{"title":"x"}`, "", "", "k")
	require.NoError(t, err)
	assert.Equal(t, finding.ResultID(victimTenant, "spiffe://zeroroot.ai/agent/x", "k").String(), raw)
}

func TestNewGraphRAGFindingSubmitter_RequiresAStore(t *testing.T) {
	assert.Panics(t, func() { NewGraphRAGFindingSubmitter(nil, nil, nil, testLogger()) })
}

// Postgres is the one home of the fields and the evidence of a finding. A
// failed write fails the submit, and the World never hears of the finding.
func TestFindingSubmitter_AStoreFailureFailsTheSubmitBeforeTheWorld(t *testing.T) {
	for name, cause := range map[string]error{
		"connection down": errors.New("postgres down"),
		"not provisioned": &datapool.NotProvisionedError{Tenant: victimTenant},
	} {
		t.Run(name, func(t *testing.T) {
			var seen finding.EnhancedFinding
			submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), poolStore(failingPool{err: cause}), nil, testLogger())

			id, err := submitter.Submit(submitterCtx(victimTenant, "agent_principal:sa-1"),
				victimTenant, "", `{"title":"exposed admin panel","severity":"info"}`, "", "", "")

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
			submitter := NewGraphRAGFindingSubmitter(recordingSink(&seen), poolStore(failingPool{err: tc.cause}), nil, testLogger())
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
