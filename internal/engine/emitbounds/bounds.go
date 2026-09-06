// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package emitbounds declares the payload limits every agent emit is held to,
// and the checks that enforce them.
//
// The emitter is remote and untrusted (ADR-0012, "Write contract"), so the emit
// contract carries explicit caps rather than trusting the producer: maximum
// payload bytes, maximum properties per observation, maximum property-key
// length, and maximum observations per task.
//
// # Rejected, never truncated
//
// Over-limit input is refused. Nothing here truncates, evicts, or elides — a
// half-written finding that looks complete is worse than a rejected one in a
// system whose whole output is evidence. This is the opposite policy to
// harness.SizeEnforcer, which truncates compliance tag bags: tags are
// annotation, observations are the evidence itself.
//
// # Property keys are data, not schema
//
// Promoted types take their properties from the Taxonomy. Everything else lives
// inside the observation payload map, where keys are map entries passed as
// query parameters — so unbounded keys are a schema-sprawl and memory concern,
// not an injection one, and MaxProperties and MaxPropertyKeyBytes are what
// address them.
//
// # One place
//
// These four constants are the single declaration of the emit bounds. Ingress
// handlers call the checks; they do not restate the numbers.
package emitbounds

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// The emit bounds. Magnitudes follow the sandbox path's existing 100 KiB
// input guard (harness/sandboxed.maxInputBytes) and the 256-entry cap the
// compliance tag merger already uses (harness.MaxEntryCount).
const (
	// MaxPayloadBytes caps the serialized size of a single emitted
	// observation. 100 KiB, matching the sandbox input guard.
	MaxPayloadBytes = 100 * 1024

	// MaxProperties caps the number of entries in any one property map
	// carried by an observation — the top-level payload map and every
	// nested object alike.
	MaxProperties = 256

	// MaxPropertyKeyBytes caps the length of a single property key.
	MaxPropertyKeyBytes = 128

	// MaxObservationsPerTask caps how many observations one task may emit.
	MaxObservationsPerTask = 1000
)

// Limit names, used as the Limit field of a LimitError and in its message so
// the caller is told which cap it hit.
const (
	LimitPayloadBytes        = "payload bytes"
	LimitProperties          = "properties per observation"
	LimitPropertyKeyBytes    = "property key bytes"
	LimitObservationsPerTask = "observations per task"
)

// ErrLimitExceeded matches every LimitError under errors.Is, so an ingress
// handler can map the whole class to one gRPC status without switching on
// which cap was hit.
var ErrLimitExceeded = errors.New("emit bounds exceeded")

// LimitError reports that an emit was refused because it exceeded a cap. It
// names the cap, the observed value and the maximum, so the emitter can tell
// what to fix. Nothing was written: a LimitError always means the emit was
// rejected whole.
type LimitError struct {
	// Limit is one of the Limit* constants.
	Limit string
	// Observed is the value the payload presented.
	Observed int
	// Max is the cap Observed exceeded.
	Max int
	// Context optionally names where in the payload the violation was found
	// (for example the offending property key). May be empty.
	Context string
}

func (e *LimitError) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("emit rejected: %s limit exceeded (%d > %d) at %s; nothing was written",
			e.Limit, e.Observed, e.Max, e.Context)
	}
	return fmt.Sprintf("emit rejected: %s limit exceeded (%d > %d); nothing was written",
		e.Limit, e.Observed, e.Max)
}

// Is reports whether target is ErrLimitExceeded, so errors.Is(err,
// ErrLimitExceeded) holds for every LimitError.
func (e *LimitError) Is(target error) bool { return target == ErrLimitExceeded }

// CheckPayloadBytes rejects a serialized observation larger than
// MaxPayloadBytes. Call it before parsing: the point of the cap is that an
// untrusted blob is measured before it is decoded.
func CheckPayloadBytes(n int) error {
	if n > MaxPayloadBytes {
		return &LimitError{Limit: LimitPayloadBytes, Observed: n, Max: MaxPayloadBytes}
	}
	return nil
}

// CheckPayload validates an already-serialized observation payload: its byte
// size first, then — once it is known to be small enough to decode safely —
// the property count and key length of every object inside it.
//
// A payload that is not valid JSON is rejected too; an emit the daemon cannot
// read is not an emit it should half-accept.
func CheckPayload(payload []byte) error {
	if err := CheckPayloadBytes(len(payload)); err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return fmt.Errorf("emit rejected: payload is not valid JSON: %w", err)
	}
	return checkValue(decoded, "payload")
}

// CheckObservation serializes v and validates it against every bound. Use it
// on the in-process path, where the observation arrives as a Go value rather
// than as bytes.
func CheckObservation(v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("emit rejected: observation is not serializable: %w", err)
	}
	if err := CheckPayloadBytes(len(payload)); err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return fmt.Errorf("emit rejected: observation is not valid JSON: %w", err)
	}
	return checkValue(decoded, "observation")
}

// checkValue walks a decoded payload, applying MaxProperties to every object
// and MaxPropertyKeyBytes to every key. Recursion depth is bounded in practice
// by MaxPayloadBytes, which the caller has already enforced.
func checkValue(v any, path string) error {
	switch typed := v.(type) {
	case map[string]any:
		if len(typed) > MaxProperties {
			return &LimitError{
				Limit:    LimitProperties,
				Observed: len(typed),
				Max:      MaxProperties,
				Context:  path,
			}
		}
		for key, val := range typed {
			if len(key) > MaxPropertyKeyBytes {
				return &LimitError{
					Limit:    LimitPropertyKeyBytes,
					Observed: len(key),
					Max:      MaxPropertyKeyBytes,
					Context:  path + "." + elide(key),
				}
			}
			if err := checkValue(val, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for i, val := range typed {
			if err := checkValue(val, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// elide shortens an over-long key so the error message naming it stays a
// message rather than becoming a copy of the payload.
func elide(key string) string {
	const keep = 32
	if len(key) <= keep {
		return key
	}
	return key[:keep] + "..."
}

// Counter bounds how many observations one task may emit. Its zero value is
// ready to use, and it is meant to be embedded in whatever object already has
// the task's lifetime — the per-task harness, typically — so that bounding the
// emit does not reintroduce the unbounded map the bound exists to prevent.
type Counter struct {
	mu sync.Mutex
	n  int
}

// Admit records one more observation for the task, or refuses when the task
// has already emitted MaxObservationsPerTask. A refused Admit does not consume
// budget: the count is unchanged, so the error is reproducible.
func (c *Counter) Admit() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n >= MaxObservationsPerTask {
		return &LimitError{
			Limit:    LimitObservationsPerTask,
			Observed: c.n + 1,
			Max:      MaxObservationsPerTask,
		}
	}
	c.n++
	return nil
}

// Count returns how many observations the task has emitted.
func (c *Counter) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// maxTrackedTasks bounds how many task counters a TaskCounter holds at once,
// so the bookkeeping for a memory bound is itself bounded.
const maxTrackedTasks = 4096

// TaskCounter is a keyed pool of Counters, for ingress points that have a task
// identifier on the wire but no per-task object to hang a Counter on.
//
// It tracks at most maxTrackedTasks tasks; admitting a new task once the pool
// is full forgets the least recently admitted one. That is deliberate: a
// counter that grows without limit would be the same memory problem this
// package exists to prevent, and the per-observation caps — which no eviction
// can relax — remain in force regardless. Callers that know when a task ends
// should call Forget so eviction stays theoretical.
type TaskCounter struct {
	mu       sync.Mutex
	counters map[string]*Counter
	order    []string
}

// NewTaskCounter returns an empty TaskCounter.
func NewTaskCounter() *TaskCounter {
	return &TaskCounter{counters: make(map[string]*Counter)}
}

// Admit records one more observation for taskID, or refuses when that task has
// already emitted MaxObservationsPerTask.
func (t *TaskCounter) Admit(taskID string) error {
	t.mu.Lock()
	counter, ok := t.counters[taskID]
	if !ok {
		if t.counters == nil {
			t.counters = make(map[string]*Counter)
		}
		counter = &Counter{}
		t.counters[taskID] = counter
		t.order = append(t.order, taskID)
		for len(t.order) > maxTrackedTasks {
			evicted := t.order[0]
			t.order = t.order[1:]
			delete(t.counters, evicted)
		}
	}
	t.mu.Unlock()
	return counter.Admit()
}

// Forget drops the counter for taskID. Call it when a task ends.
func (t *TaskCounter) Forget(taskID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.counters, taskID)
	for i, id := range t.order {
		if id == taskID {
			t.order = append(t.order[:i], t.order[i+1:]...)
			break
		}
	}
}
