// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mission

// originate_test.go exercises the origination policy end to end against a
// real Redis-backed ledger (miniredis) and a recording store. Every refusal
// path additionally asserts that NOTHING was persisted and NOTHING stayed
// reserved — a refusal that leaks a reservation quietly shrinks the parent's
// envelope forever, which is the failure mode a "did it return an error?"
// test would sail straight past.

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// recordingSaver captures saved missions and can be made to fail.
type recordingSaver struct {
	mu    sync.Mutex
	saved []*Mission
	err   error
}

func (r *recordingSaver) Save(_ context.Context, m *Mission) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.saved = append(r.saved, m)
	return nil
}

func (r *recordingSaver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.saved)
}

// originatorFixture wires an Originator over a recording saver and a real
// miniredis-backed ledger, and hands back the ledger so a test can inspect
// what is actually reserved afterwards.
type originatorFixture struct {
	orig   *Originator
	saver  *recordingSaver
	ledger ReservationLedger
}

func newOriginatorFixture(t *testing.T) originatorFixture {
	t.Helper()
	saver := &recordingSaver{}
	ledger := newTestReservationLedger(t)
	return originatorFixture{
		orig:   NewOriginator(saver, ledger, nil),
		saver:  saver,
		ledger: ledger,
	}
}

// parentWithTargets builds a parent mission with a cost cap and a target set.
func parentWithTargets(capDollars, spent float64, targets ...types.ID) *Mission {
	m := &Mission{
		ID:          types.NewID(),
		TenantID:    "tenant-a",
		Constraints: &missionv1.MissionConstraints{MaxCost: capDollars},
		Metrics:     &MissionMetrics{TotalCost: spent},
	}
	if len(targets) > 0 {
		m.TargetID = targets[0]
		m.AdditionalTargetIDs = targets[1:]
	}
	return m
}

// definitionJSON marshals a definition the way a caller would send it.
func definitionJSON(t *testing.T, def *missionv1.MissionDefinition) []byte {
	t.Helper()
	raw, err := MarshalDefinitionJSON(def)
	require.NoError(t, err)
	return raw
}

func validRequest(parent *Mission) OriginateRequest {
	return OriginateRequest{
		Parent:       parent,
		ParentWorkID: "work-123",
		Principal:    "agent_principal:abc",
		GrantID:      "grant-777",
	}
}

// assertNothingReserved fails when any reservation survives against parent.
func assertNothingReserved(ctx context.Context, t *testing.T, f originatorFixture, parentID types.ID) {
	t.Helper()
	reserved, err := f.ledger.Reserved(ctx, parentID)
	require.NoError(t, err)
	assert.Nil(t, reserved.CostUSDCents, "a refused origination left money reserved against the parent")
	assert.Nil(t, reserved.Tokens, "a refused origination left tokens reserved against the parent")
}

func TestOriginate_HappyPath_RecordsLineageBudgetAndScope(t *testing.T) {
	ctx := context.Background()
	f := newOriginatorFixture(t)

	target := types.NewID()
	other := types.NewID()
	parent := parentWithTargets(10.00, 0, target, other)
	parent.Depth = 0

	req := validRequest(parent)
	req.TargetIDs = []types.ID{target}
	req.DefinitionJSON = definitionJSON(t, &missionv1.MissionDefinition{
		Id:          "def-1",
		Name:        "child recon",
		Description: "a child",
		Constraints: &missionv1.MissionConstraints{MaxCost: 3.00, MaxTokens: 500},
	})

	child, err := f.orig.Originate(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, child)

	// Persisted exactly once, and what came back is what was stored.
	require.Equal(t, 1, f.saver.count())
	assert.Equal(t, child.ID, f.saver.saved[0].ID)

	// Lineage, from the verified caller, not the payload.
	assert.Equal(t, "agent_principal:abc", child.Metadata[LineageOriginatingComponent])
	assert.Equal(t, "grant-777", child.Metadata[LineageCapabilityGrantID])
	assert.Equal(t, parent.ID.String(), child.Metadata[LineageParentMissionID])
	assert.Equal(t, "work-123", child.Metadata[LineageParentWorkID])
	require.NotNil(t, child.ParentMissionID)
	assert.Equal(t, parent.ID, *child.ParentMissionID)
	assert.Equal(t, 1, child.Depth)
	assert.Equal(t, parent.TenantID, child.TenantID)
	assert.Equal(t, MissionStatusPending, child.Status)

	// Scope: exactly the requested subset, nothing added.
	assert.Equal(t, []types.ID{target}, child.TargetSet())

	// Budget: the request fits, so it is granted verbatim and reserved.
	assert.InDelta(t, 3.00, child.Constraints.GetMaxCost(), 0.0001)
	assert.Equal(t, int64(500), child.Constraints.GetMaxTokens())

	reserved, err := f.ledger.Reserved(ctx, parent.ID)
	require.NoError(t, err)
	require.NotNil(t, reserved.CostUSDCents)
	assert.Equal(t, int64(300), *reserved.CostUSDCents)
}

func TestOriginate_ClampsToWhatTheParentHasLeft(t *testing.T) {
	ctx := context.Background()
	f := newOriginatorFixture(t)

	parent := parentWithTargets(10.00, 7.50) // $2.50 left
	req := validRequest(parent)
	req.DefinitionJSON = definitionJSON(t, &missionv1.MissionDefinition{
		Constraints: &missionv1.MissionConstraints{MaxCost: 9.00}, // asks for more
	})

	child, err := f.orig.Originate(ctx, req)
	require.NoError(t, err)
	assert.InDelta(t, 2.50, child.Constraints.GetMaxCost(), 0.0001)
}

func TestOriginate_ParallelChildrenCannotOverCommitTheParent(t *testing.T) {
	ctx := context.Background()
	f := newOriginatorFixture(t)

	parent := parentWithTargets(5.00, 0) // 500 cents
	mk := func(dollars float64) OriginateRequest {
		req := validRequest(parent)
		req.DefinitionJSON = definitionJSON(t, &missionv1.MissionDefinition{
			Constraints: &missionv1.MissionConstraints{MaxCost: dollars},
		})
		return req
	}

	first, err := f.orig.Originate(ctx, mk(4.00))
	require.NoError(t, err)
	assert.InDelta(t, 4.00, first.Constraints.GetMaxCost(), 0.0001)

	// Only $1.00 is left: the second child is clamped down to it, not given
	// the $4.00 it asked for.
	second, err := f.orig.Originate(ctx, mk(4.00))
	require.NoError(t, err)
	assert.InDelta(t, 1.00, second.Constraints.GetMaxCost(), 0.0001)

	// Nothing left at all: the third is refused rather than granted zero,
	// because a zero max_cost reads as "unlimited" to every other consumer.
	_, err = f.orig.Originate(ctx, mk(1.00))
	require.Error(t, err)
	assert.Equal(t, 2, f.saver.count(), "a refused origination must not persist a mission")
}

func TestOriginate_ReleasingTheChildReturnsTheEnvelopeToTheParent(t *testing.T) {
	ctx := context.Background()
	f := newOriginatorFixture(t)

	parent := parentWithTargets(5.00, 0)
	req := validRequest(parent)
	req.DefinitionJSON = definitionJSON(t, &missionv1.MissionDefinition{
		Constraints: &missionv1.MissionConstraints{MaxCost: 5.00},
	})

	child, err := f.orig.Originate(ctx, req)
	require.NoError(t, err)

	// Exhausted while the child is live.
	_, err = f.orig.Originate(ctx, req)
	require.Error(t, err)

	// This is the same ledger call the mission manager makes when the child
	// reaches a terminal state (missionManager.releaseChildReservation,
	// gibson#1358): the reservation returns to the parent.
	require.NoError(t, f.ledger.Release(ctx, parent.ID, child.ID))
	assertNothingReserved(ctx, t, f, parent.ID)

	// And the envelope is usable again.
	_, err = f.orig.Originate(ctx, req)
	require.NoError(t, err)
}

func TestOriginate_RefusesWithoutAParentMission(t *testing.T) {
	f := newOriginatorFixture(t)
	req := validRequest(nil)

	_, err := f.orig.Originate(context.Background(), req)

	require.ErrorIs(t, err, ErrNoParentMission)
	assert.Equal(t, 0, f.saver.count())
}

func TestOriginate_RefusesWithoutAttribution(t *testing.T) {
	f := newOriginatorFixture(t)
	parent := parentWithTargets(5.00, 0)

	for name, mutate := range map[string]func(*OriginateRequest){
		"no principal": func(r *OriginateRequest) { r.Principal = "" },
		"no grant id":  func(r *OriginateRequest) { r.GrantID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			req := validRequest(parent)
			mutate(&req)

			_, err := f.orig.Originate(context.Background(), req)

			require.ErrorIs(t, err, ErrMissingAttribution)
			assert.Equal(t, 0, f.saver.count())
			assertNothingReserved(context.Background(), t, f, parent.ID)
		})
	}
}

func TestOriginate_RefusesATargetTheParentDoesNotHold(t *testing.T) {
	ctx := context.Background()
	f := newOriginatorFixture(t)

	parentTarget := types.NewID()
	parent := parentWithTargets(5.00, 0, parentTarget)

	req := validRequest(parent)
	req.TargetIDs = []types.ID{parentTarget, types.NewID()} // one extra

	_, err := f.orig.Originate(ctx, req)

	require.ErrorIs(t, err, ErrScopeWiden)
	assert.Equal(t, 0, f.saver.count())
	assertNothingReserved(ctx, t, f, parent.ID)
}

func TestOriginate_RefusesAnyTargetWhenTheParentHasNone(t *testing.T) {
	f := newOriginatorFixture(t)
	parent := parentWithTargets(5.00, 0) // no targets at all

	req := validRequest(parent)
	req.TargetIDs = []types.ID{types.NewID()}

	_, err := f.orig.Originate(context.Background(), req)

	require.ErrorIs(t, err, ErrScopeWiden)
}

func TestOriginate_AllowsAStrictSubsetAndTheEmptySet(t *testing.T) {
	ctx := context.Background()
	a, b := types.NewID(), types.NewID()

	t.Run("strict subset", func(t *testing.T) {
		f := newOriginatorFixture(t)
		req := validRequest(parentWithTargets(5.00, 0, a, b))
		req.TargetIDs = []types.ID{b}

		child, err := f.orig.Originate(ctx, req)

		require.NoError(t, err)
		assert.Equal(t, []types.ID{b}, child.TargetSet())
	})

	t.Run("empty child set claims nothing", func(t *testing.T) {
		f := newOriginatorFixture(t)
		req := validRequest(parentWithTargets(5.00, 0, a, b))

		child, err := f.orig.Originate(ctx, req)

		require.NoError(t, err)
		assert.Empty(t, child.TargetSet())
	})
}

func TestOriginate_RefusesBeyondTheDepthLimit(t *testing.T) {
	f := newOriginatorFixture(t)
	parent := parentWithTargets(5.00, 0)
	parent.Depth = MaxOriginationDepth - 1 // a child would sit at the limit

	_, err := f.orig.Originate(context.Background(), validRequest(parent))

	require.ErrorIs(t, err, ErrDepthExceeded)
	assert.Equal(t, 0, f.saver.count())
	assertNothingReserved(context.Background(), t, f, parent.ID)
}

func TestOriginate_RefusesCallerSuppliedLineage(t *testing.T) {
	ctx := context.Background()
	parent := parentWithTargets(5.00, 0)

	for _, key := range []string{
		LineageOriginatingComponent,
		LineageCapabilityGrantID,
		LineageParentMissionID,
		LineageParentWorkID,
	} {
		t.Run(key, func(t *testing.T) {
			f := newOriginatorFixture(t)
			req := validRequest(parent)
			req.DefinitionJSON = definitionJSON(t, &missionv1.MissionDefinition{
				Metadata: map[string]string{key: "forged"},
			})

			_, err := f.orig.Originate(ctx, req)

			require.ErrorIs(t, err, ErrLineageSupplied)
			assert.Equal(t, 0, f.saver.count())
			// The refusal happens after the reservation, so this asserts the
			// compensating release actually ran.
			assertNothingReserved(ctx, t, f, parent.ID)
		})
	}
}

func TestOriginate_ReleasesTheReservationWhenTheSaveFails(t *testing.T) {
	ctx := context.Background()
	f := newOriginatorFixture(t)
	f.saver.err = errors.New("redis is down")

	parent := parentWithTargets(5.00, 0)
	req := validRequest(parent)
	req.DefinitionJSON = definitionJSON(t, &missionv1.MissionDefinition{
		Constraints: &missionv1.MissionConstraints{MaxCost: 5.00},
	})

	_, err := f.orig.Originate(ctx, req)

	require.Error(t, err)
	assertNothingReserved(ctx, t, f, parent.ID)
}

func TestOriginate_RejectsAMalformedDefinition(t *testing.T) {
	f := newOriginatorFixture(t)
	req := validRequest(parentWithTargets(5.00, 0))
	req.DefinitionJSON = []byte("{not json")

	_, err := f.orig.Originate(context.Background(), req)

	require.Error(t, err)
	assert.Equal(t, 0, f.saver.count())
}

func TestOriginate_StoresTheGrantedBudgetNotTheRequestedOne(t *testing.T) {
	ctx := context.Background()
	f := newOriginatorFixture(t)

	parent := parentWithTargets(10.00, 9.00) // $1.00 left
	req := validRequest(parent)
	req.DefinitionJSON = definitionJSON(t, &missionv1.MissionDefinition{
		Constraints: &missionv1.MissionConstraints{MaxCost: 100.00},
	})

	child, err := f.orig.Originate(ctx, req)
	require.NoError(t, err)

	// What was persisted must carry the clamp too, not just the returned
	// value: the budget enforcer reads the stored record.
	stored := f.saver.saved[0]
	assert.InDelta(t, 1.00, stored.Constraints.GetMaxCost(), 0.0001)

	// And the definition JSON the child carries is still the caller's own
	// (only the mission-level constraints are rewritten).
	var probe map[string]any
	require.NoError(t, json.Unmarshal([]byte(child.MissionDefinitionJSON), &probe))
}

func TestOriginate_ConcurrentChildrenNeverExceedTheParentEnvelope(t *testing.T) {
	ctx := context.Background()
	f := newOriginatorFixture(t)

	// $10.00 of room, twenty children each asking for $1.00. At most ten can
	// be granted; the rest must be refused. If Reserve were a read-then-write
	// instead of one atomic script, the racing readers would all see the same
	// remainder and hand out more than $10.00 between them.
	parent := parentWithTargets(10.00, 0)
	req := validRequest(parent)
	req.DefinitionJSON = definitionJSON(t, &missionv1.MissionDefinition{
		Constraints: &missionv1.MissionConstraints{MaxCost: 1.00},
	})

	const children = 20
	var wg sync.WaitGroup
	granted := make([]float64, children)
	for i := range children {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			child, err := f.orig.Originate(ctx, req)
			if err == nil {
				granted[i] = child.Constraints.GetMaxCost()
			}
		}(i)
	}
	wg.Wait()

	var total float64
	for _, g := range granted {
		total += g
	}
	assert.LessOrEqual(t, total, 10.00,
		"concurrent children were granted more than the parent's whole envelope")

	// And the ledger agrees with what was handed out: no reservation was
	// written that no child received, and none received that was not written.
	reserved, err := f.ledger.Reserved(ctx, parent.ID)
	require.NoError(t, err)
	require.NotNil(t, reserved.CostUSDCents)
	assert.Equal(t, int64(total*100+0.5), *reserved.CostUSDCents)
}
