// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package emitbounds

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// jsonOfSize returns a valid JSON object whose serialized form is exactly n
// bytes. The wrapper {"a":""} is 8 bytes, so the padding takes the rest.
func jsonOfSize(t *testing.T, n int) []byte {
	t.Helper()
	// The fixed overhead of the enclosing object, leaving the rest to padding.
	const wrapper = 8
	if n < wrapper {
		t.Fatalf("cannot build a JSON object of %d bytes", n)
	}
	payload := []byte(`{"a":"` + strings.Repeat("x", n-wrapper) + `"}`)
	if len(payload) != n {
		t.Fatalf("built payload of %d bytes, want %d", len(payload), n)
	}
	if !json.Valid(payload) {
		t.Fatalf("built payload is not valid JSON")
	}
	return payload
}

// mapOfSize returns a JSON object with exactly n distinct keys.
func mapOfSize(n int) []byte {
	m := make(map[string]int, n)
	for i := range n {
		m[fmt.Sprintf("k%d", i)] = i
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return encoded
}

// ---------------------------------------------------------------------------
// Boundary pairs: at the limit is accepted, one over is rejected.
// ---------------------------------------------------------------------------

func TestPayloadBytesBoundary(t *testing.T) {
	t.Run("at the limit is accepted", func(t *testing.T) {
		if err := CheckPayload(jsonOfSize(t, MaxPayloadBytes)); err != nil {
			t.Fatalf("payload of exactly MaxPayloadBytes rejected: %v", err)
		}
	})

	t.Run("one byte over is rejected", func(t *testing.T) {
		err := CheckPayload(jsonOfSize(t, MaxPayloadBytes+1))
		if err == nil {
			t.Fatal("payload of MaxPayloadBytes+1 accepted; want rejection")
		}
		assertLimit(t, err, LimitPayloadBytes, MaxPayloadBytes+1, MaxPayloadBytes)
	})
}

func TestPropertyCountBoundary(t *testing.T) {
	t.Run("at the limit is accepted", func(t *testing.T) {
		if err := CheckPayload(mapOfSize(MaxProperties)); err != nil {
			t.Fatalf("object with exactly MaxProperties keys rejected: %v", err)
		}
	})

	t.Run("one property over is rejected", func(t *testing.T) {
		err := CheckPayload(mapOfSize(MaxProperties + 1))
		if err == nil {
			t.Fatal("object with MaxProperties+1 keys accepted; want rejection")
		}
		assertLimit(t, err, LimitProperties, MaxProperties+1, MaxProperties)
	})

	t.Run("the cap applies to nested objects too", func(t *testing.T) {
		nested, err := json.Marshal(map[string]any{
			"evidence": []any{map[string]any{"data": json.RawMessage(mapOfSize(MaxProperties + 1))}},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := CheckPayload(nested); err == nil {
			t.Fatal("over-limit map nested under an array accepted; want rejection")
		}
	})
}

func TestPropertyKeyLengthBoundary(t *testing.T) {
	t.Run("at the limit is accepted", func(t *testing.T) {
		payload, err := json.Marshal(map[string]any{strings.Repeat("k", MaxPropertyKeyBytes): 1})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := CheckPayload(payload); err != nil {
			t.Fatalf("key of exactly MaxPropertyKeyBytes rejected: %v", err)
		}
	})

	t.Run("one byte over is rejected", func(t *testing.T) {
		payload, marshalErr := json.Marshal(map[string]any{strings.Repeat("k", MaxPropertyKeyBytes+1): 1})
		if marshalErr != nil {
			t.Fatalf("marshal: %v", marshalErr)
		}
		err := CheckPayload(payload)
		if err == nil {
			t.Fatal("key of MaxPropertyKeyBytes+1 accepted; want rejection")
		}
		assertLimit(t, err, LimitPropertyKeyBytes, MaxPropertyKeyBytes+1, MaxPropertyKeyBytes)
	})
}

func TestObservationsPerTaskBoundary(t *testing.T) {
	t.Run("the last observation at the limit is accepted", func(t *testing.T) {
		var counter Counter
		for i := range MaxObservationsPerTask {
			if err := counter.Admit(); err != nil {
				t.Fatalf("observation %d of MaxObservationsPerTask rejected: %v", i+1, err)
			}
		}
		if got := counter.Count(); got != MaxObservationsPerTask {
			t.Fatalf("count = %d, want %d", got, MaxObservationsPerTask)
		}
	})

	t.Run("one observation over is rejected", func(t *testing.T) {
		var counter Counter
		for range MaxObservationsPerTask {
			if err := counter.Admit(); err != nil {
				t.Fatalf("unexpected rejection under the limit: %v", err)
			}
		}
		err := counter.Admit()
		if err == nil {
			t.Fatal("observation MaxObservationsPerTask+1 accepted; want rejection")
		}
		assertLimit(t, err, LimitObservationsPerTask, MaxObservationsPerTask+1, MaxObservationsPerTask)
	})

	t.Run("a refused Admit consumes no budget", func(t *testing.T) {
		var counter Counter
		for range MaxObservationsPerTask {
			_ = counter.Admit()
		}
		for range 5 {
			if err := counter.Admit(); err == nil {
				t.Fatal("over-limit Admit accepted")
			}
		}
		if got := counter.Count(); got != MaxObservationsPerTask {
			t.Fatalf("refused Admits moved the count to %d; want it pinned at %d", got, MaxObservationsPerTask)
		}
	})

	t.Run("each task has its own budget", func(t *testing.T) {
		tasks := NewTaskCounter()
		for range MaxObservationsPerTask {
			if err := tasks.Admit("task-a"); err != nil {
				t.Fatalf("unexpected rejection under the limit: %v", err)
			}
		}
		if err := tasks.Admit("task-a"); err == nil {
			t.Fatal("task-a admitted past its limit")
		}
		if err := tasks.Admit("task-b"); err != nil {
			t.Fatalf("task-b charged against task-a's budget: %v", err)
		}
	})

	t.Run("Forget releases a task's budget", func(t *testing.T) {
		tasks := NewTaskCounter()
		for range MaxObservationsPerTask {
			_ = tasks.Admit("task-a")
		}
		if err := tasks.Admit("task-a"); err == nil {
			t.Fatal("task-a admitted past its limit")
		}
		tasks.Forget("task-a")
		if err := tasks.Admit("task-a"); err != nil {
			t.Fatalf("Forget did not release the budget: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Rejected, never truncated.
// ---------------------------------------------------------------------------

// TestOverLimitIsRejectedNotTruncated is the load-bearing test: an over-limit
// payload must produce an error and must not come back shortened, trimmed or
// otherwise partially accepted. Silent truncation corrupts data in a system
// whose whole output is evidence (ADR-0012).
func TestOverLimitIsRejectedNotTruncated(t *testing.T) {
	t.Run("over-size payload is not shortened", func(t *testing.T) {
		payload := jsonOfSize(t, MaxPayloadBytes+1024)
		before := append([]byte(nil), payload...)

		err := CheckPayload(payload)
		if err == nil {
			t.Fatal("over-size payload accepted; want rejection")
		}
		if !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("error does not match ErrLimitExceeded: %v", err)
		}
		if !bytes.Equal(payload, before) {
			t.Fatal("CheckPayload mutated the payload; over-limit input must be rejected, never truncated")
		}
	})

	t.Run("over-count property map is not evicted from", func(t *testing.T) {
		observation := map[string]any{}
		for i := range MaxProperties + 1 {
			observation[fmt.Sprintf("k%d", i)] = i
		}

		err := CheckObservation(observation)
		if err == nil {
			t.Fatal("over-count property map accepted; want rejection")
		}
		if len(observation) != MaxProperties+1 {
			t.Fatalf("CheckObservation evicted entries (map is now %d); over-limit input must be rejected, never trimmed",
				len(observation))
		}
	})

	t.Run("over-long key is not cut down", func(t *testing.T) {
		key := strings.Repeat("k", MaxPropertyKeyBytes+64)
		observation := map[string]any{key: "v"}

		err := CheckObservation(observation)
		if err == nil {
			t.Fatal("over-long key accepted; want rejection")
		}
		if _, ok := observation[key]; !ok {
			t.Fatal("CheckObservation rewrote the key; over-limit input must be rejected, never truncated")
		}
	})
}

// ---------------------------------------------------------------------------
// Error reporting: the caller is told which limit it hit.
// ---------------------------------------------------------------------------

func TestLimitErrorNamesTheLimit(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		wantSub string
	}{
		{"payload bytes", CheckPayload(jsonOfSize(t, MaxPayloadBytes+1)), LimitPayloadBytes},
		{"property count", CheckPayload(mapOfSize(MaxProperties + 1)), LimitProperties},
		{"key length", CheckObservation(map[string]any{strings.Repeat("k", MaxPropertyKeyBytes+1): 1}), LimitPropertyKeyBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err == nil {
				t.Fatal("expected a rejection")
			}
			if !strings.Contains(tc.err.Error(), tc.wantSub) {
				t.Errorf("error %q does not name the limit %q", tc.err, tc.wantSub)
			}
			if !strings.Contains(tc.err.Error(), "nothing was written") {
				t.Errorf("error %q does not say the emit left no state", tc.err)
			}
			if !errors.Is(tc.err, ErrLimitExceeded) {
				t.Errorf("error %v does not match ErrLimitExceeded", tc.err)
			}
		})
	}
}

func TestNonJSONPayloadIsRejected(t *testing.T) {
	if err := CheckPayload([]byte("not json at all")); err == nil {
		t.Fatal("unparseable payload accepted; want rejection")
	}
}

func TestUnderLimitPayloadIsAccepted(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"title":    "open redirect",
		"severity": "medium",
		"metadata": map[string]any{"tool": "probe"},
		"evidence": []any{map[string]any{"data": map[string]any{"url": "http://example.test"}}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := CheckPayload(payload); err != nil {
		t.Fatalf("ordinary finding rejected: %v", err)
	}
}

func TestCounterIsConcurrencySafe(t *testing.T) {
	var counter Counter
	var wg sync.WaitGroup
	const goroutines = 8
	const each = MaxObservationsPerTask // together, 8x the limit

	admitted := make([]int, goroutines)
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				if err := counter.Admit(); err == nil {
					admitted[g]++
				}
			}
		}()
	}
	wg.Wait()

	total := 0
	for _, n := range admitted {
		total += n
	}
	if total != MaxObservationsPerTask {
		t.Fatalf("admitted %d observations concurrently; want exactly %d", total, MaxObservationsPerTask)
	}
	if got := counter.Count(); got != MaxObservationsPerTask {
		t.Fatalf("count = %d, want %d", got, MaxObservationsPerTask)
	}
}

func assertLimit(t *testing.T, err error, wantLimit string, wantObserved, wantMax int) {
	t.Helper()
	var limitErr *LimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("error %v is not a *LimitError", err)
	}
	if limitErr.Limit != wantLimit {
		t.Errorf("Limit = %q, want %q", limitErr.Limit, wantLimit)
	}
	if limitErr.Observed != wantObserved {
		t.Errorf("Observed = %d, want %d", limitErr.Observed, wantObserved)
	}
	if limitErr.Max != wantMax {
		t.Errorf("Max = %d, want %d", limitErr.Max, wantMax)
	}
}
