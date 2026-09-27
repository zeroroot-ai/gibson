// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package settlement

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
)

const (
	testTechnique     TechniqueID   = "T1190"
	otherTechnique    TechniqueID   = "T1059"
	testPredicateType PredicateType = "always_true_for_test"
)

// alwaysTrue is a trivial, deterministic evaluator used only to exercise the
// registry mechanics; it never calls an LLM and reads only its inputs.
func alwaysTrue(_ json.RawMessage, _ []finding.EnhancedEvidence) (bool, error) {
	return true, nil
}

func alwaysFalse(_ json.RawMessage, _ []finding.EnhancedEvidence) (bool, error) {
	return false, nil
}

func TestRegistry_Register(t *testing.T) {
	t.Run("registers a new technique/type pair", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register(testTechnique, testPredicateType, alwaysTrue)
		require.NoError(t, err)
		assert.True(t, r.Registered(testTechnique, testPredicateType))
	})

	t.Run("rejects empty technique", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register("", testPredicateType, alwaysTrue)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyTechnique)
	})

	t.Run("rejects empty predicate type", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register(testTechnique, "", alwaysTrue)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyPredicateType)
	})

	t.Run("rejects nil evaluator", func(t *testing.T) {
		r := NewRegistry()
		err := r.Register(testTechnique, testPredicateType, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilEvaluator)
	})

	t.Run("rejects a duplicate registration for the same technique", func(t *testing.T) {
		r := NewRegistry()
		require.NoError(t, r.Register(testTechnique, testPredicateType, alwaysTrue))

		err := r.Register(testTechnique, testPredicateType, alwaysFalse)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAlreadyRegistered)
	})

	t.Run("the same predicate type may be registered under a different technique", func(t *testing.T) {
		// Anti-gaming isolation: a predicate type is scoped per technique.
		// Two techniques defining a type of the same name are independent
		// entries, never a collision.
		r := NewRegistry()
		require.NoError(t, r.Register(testTechnique, testPredicateType, alwaysTrue))
		require.NoError(t, r.Register(otherTechnique, testPredicateType, alwaysFalse))

		assert.True(t, r.Registered(testTechnique, testPredicateType))
		assert.True(t, r.Registered(otherTechnique, testPredicateType))
	})
}

func TestRegistry_MustRegister(t *testing.T) {
	t.Run("does not panic on a valid registration", func(t *testing.T) {
		r := NewRegistry()
		assert.NotPanics(t, func() {
			r.MustRegister(testTechnique, testPredicateType, alwaysTrue)
		})
	})

	t.Run("panics on an invalid registration", func(t *testing.T) {
		r := NewRegistry()
		assert.Panics(t, func() {
			r.MustRegister("", testPredicateType, alwaysTrue)
		})
	})
}

func TestRegistry_NewPredicate(t *testing.T) {
	t.Run("builds a predicate for a registered type", func(t *testing.T) {
		r := NewRegistry()
		require.NoError(t, r.Register(testTechnique, testPredicateType, alwaysTrue))

		p, err := r.NewPredicate(testTechnique, testPredicateType, map[string]any{"marker": "abc"})
		require.NoError(t, err)
		assert.Equal(t, testTechnique, p.Technique)
		assert.Equal(t, testPredicateType, p.Type)
		assert.JSONEq(t, `{"marker":"abc"}`, string(p.Params))
	})

	t.Run("fails closed for an unregistered type (anti-gaming)", func(t *testing.T) {
		// A technique with no registered predicate type cannot have one
		// fabricated for it at construction time either — this is what
		// ADR-0027 decision 3 means by "cannot invent a trivially-true
		// predicate to game its own bet."
		r := NewRegistry()
		_, err := r.NewPredicate(testTechnique, "never_registered", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnregisteredPredicate)
	})

	t.Run("rejects params that cannot be marshaled", func(t *testing.T) {
		r := NewRegistry()
		require.NoError(t, r.Register(testTechnique, testPredicateType, alwaysTrue))

		_, err := r.NewPredicate(testTechnique, testPredicateType, make(chan int))
		require.Error(t, err)
	})

	t.Run("accepts already-encoded json.RawMessage params unchanged", func(t *testing.T) {
		r := NewRegistry()
		require.NoError(t, r.Register(testTechnique, testPredicateType, alwaysTrue))

		raw := json.RawMessage(`{"want":200}`)
		p, err := r.NewPredicate(testTechnique, testPredicateType, raw)
		require.NoError(t, err)
		assert.JSONEq(t, `{"want":200}`, string(p.Params))
	})
}

func TestRegistry_Evaluate(t *testing.T) {
	ctx := context.Background()

	t.Run("evaluates a registered predicate", func(t *testing.T) {
		r := NewRegistry()
		require.NoError(t, r.Register(testTechnique, testPredicateType, alwaysTrue))
		p, err := r.NewPredicate(testTechnique, testPredicateType, nil)
		require.NoError(t, err)

		ok, err := r.Evaluate(ctx, p, nil)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("fails closed when the predicate's type is not registered", func(t *testing.T) {
		r := NewRegistry()
		// Construct the predicate as data directly (bypassing NewPredicate)
		// to simulate replaying a predicate persisted before a technique's
		// registration is available, or a tampered/unknown type.
		p := Predicate{Technique: testTechnique, Type: "not_registered", Params: nil}

		ok, err := r.Evaluate(ctx, p, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnregisteredPredicate)
		assert.False(t, ok)
	})

	t.Run("rejects an invalid predicate before evaluating", func(t *testing.T) {
		r := NewRegistry()
		_, err := r.Evaluate(ctx, Predicate{}, nil)
		require.Error(t, err)
	})

	t.Run("propagates the evaluator's error", func(t *testing.T) {
		r := NewRegistry()
		boom := errors.New("boom")
		require.NoError(t, r.Register(testTechnique, testPredicateType, func(_ json.RawMessage, _ []finding.EnhancedEvidence) (bool, error) {
			return false, boom
		}))
		p, err := r.NewPredicate(testTechnique, testPredicateType, nil)
		require.NoError(t, err)

		_, err = r.Evaluate(ctx, p, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, boom)
	})

	t.Run("refuses to evaluate once the context is already canceled", func(t *testing.T) {
		r := NewRegistry()
		require.NoError(t, r.Register(testTechnique, testPredicateType, alwaysTrue))
		p, err := r.NewPredicate(testTechnique, testPredicateType, nil)
		require.NoError(t, err)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		_, err = r.Evaluate(cancelCtx, p, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// TestRegistry_Evaluate_Deterministic proves the core settlement property
// from ADR-0027 decision 2: replay re-evaluates the predicate against the
// same recorded evidence and gets the same result, every time, with no
// hidden state (wall clock, randomness, map iteration order) leaking into
// the verdict.
func TestRegistry_Evaluate_Deterministic(t *testing.T) {
	ctx := context.Background()
	r := NewRegistry()

	const markerType PredicateType = "det_marker_present"
	require.NoError(t, r.Register(testTechnique, markerType, func(params json.RawMessage, evidence []finding.EnhancedEvidence) (bool, error) {
		var p struct {
			Marker string `json:"marker"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return false, err
		}
		for _, e := range evidence {
			if s, ok := e.Content.(string); ok && s == p.Marker {
				return true, nil
			}
		}
		return false, nil
	}))

	predicate, err := r.NewPredicate(testTechnique, markerType, map[string]any{"marker": "proof-token-9f3a"})
	require.NoError(t, err)

	evidence := []finding.EnhancedEvidence{
		finding.NewEnhancedEvidence(finding.EvidenceLog, "capture", "proof-token-9f3a"),
	}

	const iterations = 200
	results := make([]bool, iterations)
	var wg sync.WaitGroup
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, evalErr := r.Evaluate(ctx, predicate, evidence)
			require.NoError(t, evalErr)
			results[i] = ok
		}(i)
	}
	wg.Wait()

	for i, ok := range results {
		assert.Truef(t, ok, "iteration %d: expected deterministic true result", i)
	}

	// Re-run sequentially against a freshly-decoded copy of the predicate
	// (as replay would reconstruct it from the graph) to prove the result
	// does not depend on object identity either.
	data, err := json.Marshal(predicate)
	require.NoError(t, err)
	var replayed Predicate
	require.NoError(t, json.Unmarshal(data, &replayed))

	ok, err := r.Evaluate(ctx, replayed, evidence)
	require.NoError(t, err)
	assert.True(t, ok)

	// Different evidence must deterministically fail the same predicate.
	ok, err = r.Evaluate(ctx, replayed, []finding.EnhancedEvidence{
		finding.NewEnhancedEvidence(finding.EvidenceLog, "capture", "wrong-token"),
	})
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestRegistry_Types(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(testTechnique, "b_type", alwaysTrue))
	require.NoError(t, r.Register(testTechnique, "a_type", alwaysTrue))
	require.NoError(t, r.Register(otherTechnique, "z_type", alwaysTrue))

	types := r.Types(testTechnique)
	assert.Equal(t, []PredicateType{"a_type", "b_type"}, types)
	assert.Empty(t, r.Types("never_seen"))
}

func TestRegistry_ConcurrentRegisterAndEvaluate(t *testing.T) {
	// Domain Pack loading (registration) and settlement (evaluation) can
	// run concurrently across missions; the registry must not race.
	r := NewRegistry()
	ctx := context.Background()
	require.NoError(t, r.Register(testTechnique, testPredicateType, alwaysTrue))
	p, err := r.NewPredicate(testTechnique, testPredicateType, nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			technique := TechniqueID("concurrent-technique")
			ptype := PredicateType("concurrent-type")
			_ = r.Register(technique, ptype, alwaysTrue) // duplicate errors are expected and fine
		}(i)

		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, evalErr := r.Evaluate(ctx, p, nil)
			assert.NoError(t, evalErr)
			assert.True(t, ok)
		}()
	}
	wg.Wait()
}
