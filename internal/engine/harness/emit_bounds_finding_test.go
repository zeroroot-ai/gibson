// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/emitbounds"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"go.opentelemetry.io/otel/trace/noop"
)

// countingFindingStore records every Store that reaches it, so a test can
// assert that a rejected emit left no partial state behind.
type countingFindingStore struct {
	FindingStore
	stored []agent.Finding
}

func (s *countingFindingStore) Store(ctx context.Context, tenantID string, missionID types.ID, finding agent.Finding) error {
	s.stored = append(s.stored, finding)
	if err := s.FindingStore.Store(ctx, tenantID, missionID, finding); err != nil {
		return fmt.Errorf("counting finding store: %w", err)
	}
	return nil
}

func boundedHarness(store FindingStore) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		logger:       slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer:       noop.NewTracerProvider().Tracer("test"),
		metrics:      &NoOpMetricsRecorder{},
		findingStore: store,
		missionCtx:   MissionContext{ID: types.NewID(), TenantID: "tenant-a"},
	}
}

// TestSubmitFindingRejectsOverSizePayload is the truncation test for the
// finding path: the over-limit finding must produce an error and must not
// arrive at the store in any form, whole or shortened.
func TestSubmitFindingRejectsOverSizePayload(t *testing.T) {
	t.Run("an ordinary finding is stored", func(t *testing.T) {
		store := &countingFindingStore{FindingStore: NewInMemoryFindingStore()}
		h := boundedHarness(store)

		err := h.SubmitFinding(context.Background(), agent.NewFinding("open redirect", "…", agent.SeverityMedium))
		if err != nil {
			t.Fatalf("ordinary finding rejected: %v", err)
		}
		if len(store.stored) != 1 {
			t.Fatalf("store saw %d findings, want 1", len(store.stored))
		}
	})

	t.Run("an over-size finding is rejected and nothing is stored", func(t *testing.T) {
		store := &countingFindingStore{FindingStore: NewInMemoryFindingStore()}
		h := boundedHarness(store)

		finding := agent.NewFinding("huge", strings.Repeat("d", emitbounds.MaxPayloadBytes), agent.SeverityHigh)
		err := h.SubmitFinding(context.Background(), finding)
		if err == nil {
			t.Fatal("over-size finding accepted; want rejection")
		}
		if !strings.Contains(err.Error(), emitbounds.LimitPayloadBytes) {
			t.Errorf("error %q does not name the limit that was exceeded", err)
		}
		if len(store.stored) != 0 {
			t.Fatalf("store saw %d findings after a rejected emit; a rejected emit must write nothing",
				len(store.stored))
		}
	})

	t.Run("a rejected finding is not stored in truncated form", func(t *testing.T) {
		store := &countingFindingStore{FindingStore: NewInMemoryFindingStore()}
		h := boundedHarness(store)

		description := strings.Repeat("d", emitbounds.MaxPayloadBytes)
		finding := agent.NewFinding("huge", description, agent.SeverityHigh)
		_ = h.SubmitFinding(context.Background(), finding)

		for _, got := range store.stored {
			if len(got.Description) < len(description) {
				t.Fatal("a shortened copy of the finding was stored; over-limit input must be rejected, never truncated")
			}
			t.Fatal("an over-limit finding was stored at all")
		}
	})
}

// TestSubmitFindingRejectsOverCountProperties covers the property caps on the
// finding's open-world metadata map — the surface the Taxonomy does not name.
func TestSubmitFindingRejectsOverCountProperties(t *testing.T) {
	t.Run("at the property limit is accepted", func(t *testing.T) {
		store := &countingFindingStore{FindingStore: NewInMemoryFindingStore()}
		h := boundedHarness(store)

		finding := agent.NewFinding("props", "…", agent.SeverityLow)
		finding.Metadata = map[string]any{}
		for i := range emitbounds.MaxProperties {
			finding.Metadata[keyN(i)] = i
		}
		if err := h.SubmitFinding(context.Background(), finding); err != nil {
			t.Fatalf("finding with exactly MaxProperties metadata keys rejected: %v", err)
		}
		if len(store.stored) != 1 {
			t.Fatalf("store saw %d findings, want 1", len(store.stored))
		}
	})

	t.Run("one property over is rejected and nothing is stored", func(t *testing.T) {
		store := &countingFindingStore{FindingStore: NewInMemoryFindingStore()}
		h := boundedHarness(store)

		finding := agent.NewFinding("props", "…", agent.SeverityLow)
		finding.Metadata = map[string]any{}
		for i := range emitbounds.MaxProperties + 1 {
			finding.Metadata[keyN(i)] = i
		}
		err := h.SubmitFinding(context.Background(), finding)
		if err == nil {
			t.Fatal("finding with MaxProperties+1 metadata keys accepted; want rejection")
		}
		if !strings.Contains(err.Error(), emitbounds.LimitProperties) {
			t.Errorf("error %q does not name the limit that was exceeded", err)
		}
		if len(store.stored) != 0 {
			t.Fatalf("store saw %d findings after a rejected emit; a rejected emit must write nothing",
				len(store.stored))
		}
	})

	t.Run("an over-long property key is rejected", func(t *testing.T) {
		store := &countingFindingStore{FindingStore: NewInMemoryFindingStore()}
		h := boundedHarness(store)

		finding := agent.NewFinding("props", "…", agent.SeverityLow)
		finding.Metadata = map[string]any{strings.Repeat("k", emitbounds.MaxPropertyKeyBytes+1): 1}
		err := h.SubmitFinding(context.Background(), finding)
		if err == nil {
			t.Fatal("finding with an over-long metadata key accepted; want rejection")
		}
		if !strings.Contains(err.Error(), emitbounds.LimitPropertyKeyBytes) {
			t.Errorf("error %q does not name the limit that was exceeded", err)
		}
		if len(store.stored) != 0 {
			t.Fatalf("store saw %d findings after a rejected emit; a rejected emit must write nothing",
				len(store.stored))
		}
	})
}

// TestSubmitFindingRejectsOverCountPerTask exercises the per-task cap on the
// harness, whose lifetime is the task's.
func TestSubmitFindingRejectsOverCountPerTask(t *testing.T) {
	store := &countingFindingStore{FindingStore: NewInMemoryFindingStore()}
	h := boundedHarness(store)

	for i := range emitbounds.MaxObservationsPerTask {
		if err := h.SubmitFinding(context.Background(), agent.NewFinding("f", "…", agent.SeverityInfo)); err != nil {
			t.Fatalf("finding %d of MaxObservationsPerTask rejected: %v", i+1, err)
		}
	}
	if len(store.stored) != emitbounds.MaxObservationsPerTask {
		t.Fatalf("store saw %d findings, want %d", len(store.stored), emitbounds.MaxObservationsPerTask)
	}

	err := h.SubmitFinding(context.Background(), agent.NewFinding("f", "…", agent.SeverityInfo))
	if err == nil {
		t.Fatal("finding MaxObservationsPerTask+1 accepted; want rejection")
	}
	if !strings.Contains(err.Error(), emitbounds.LimitObservationsPerTask) {
		t.Errorf("error %q does not name the limit that was exceeded", err)
	}
	if len(store.stored) != emitbounds.MaxObservationsPerTask {
		t.Fatalf("store saw %d findings after the over-limit emit; a rejected emit must write nothing",
			len(store.stored))
	}

	// A second task gets its own budget.
	fresh := boundedHarness(&countingFindingStore{FindingStore: NewInMemoryFindingStore()})
	if err := fresh.SubmitFinding(context.Background(), agent.NewFinding("f", "…", agent.SeverityInfo)); err != nil {
		t.Fatalf("a second task was charged against the first task's budget: %v", err)
	}
}

func keyN(i int) string {
	return "k" + strings.Repeat("0", 4-len(itoa(i))) + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}

// TestHarnessBoundsErrorStaysMatchable guards the error chain the RPC layer
// depends on. HarnessCallbackService.SubmitFinding maps a bounds rejection to
// INVALID_ARGUMENT via errors.Is(err, emitbounds.ErrLimitExceeded); the harness
// wraps that error with %w, so replacing the wrap with a fresh error would
// silently downgrade a caller's "your payload is too big" to "the daemon
// broke".
func TestHarnessBoundsErrorStaysMatchable(t *testing.T) {
	store := &countingFindingStore{FindingStore: NewInMemoryFindingStore()}
	h := boundedHarness(store)

	oversize := agent.NewFinding("huge", strings.Repeat("d", emitbounds.MaxPayloadBytes), agent.SeverityHigh)
	err := h.SubmitFinding(context.Background(), oversize)
	if err == nil {
		t.Fatal("an over-size finding was accepted")
	}
	if !errors.Is(err, emitbounds.ErrLimitExceeded) {
		t.Fatalf("harness error %v does not match emitbounds.ErrLimitExceeded; the "+
			"RPC layer maps that class to INVALID_ARGUMENT", err)
	}
	if !strings.Contains(err.Error(), emitbounds.LimitPayloadBytes) {
		t.Errorf("wrapping lost the limit name: %v", err)
	}
	if len(store.stored) != 0 {
		t.Errorf("a rejected finding reached the store %d times", len(store.stored))
	}
}
