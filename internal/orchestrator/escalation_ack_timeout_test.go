package orchestrator

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeEscalationManager implements EscalationManager with
// in-memory state, simulating the timeout / acknowledgment
// channel coordination without needing Neo4j.
type fakeEscalationManager struct {
	mu          sync.Mutex
	escalations map[string]Escalation
	waiters     map[string]chan struct{}
}

func newFakeEscalationManager() *fakeEscalationManager {
	return &fakeEscalationManager{
		escalations: make(map[string]Escalation),
		waiters:     make(map[string]chan struct{}),
	}
}

func (m *fakeEscalationManager) CreateEscalation(_ context.Context, esc Escalation) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := esc.ID
	if id == "" {
		id = "esc-" + esc.NodeID
	}
	esc.ID = id
	esc.CreatedAt = time.Now()
	m.escalations[id] = esc
	return id, nil
}

func (m *fakeEscalationManager) WaitForAcknowledgment(ctx context.Context, escalationID string, timeout time.Duration) error {
	m.mu.Lock()
	esc, ok := m.escalations[escalationID]
	if !ok {
		m.mu.Unlock()
		return &ackTimeoutError{msg: "escalation not found"}
	}
	if esc.Urgency != "critical" {
		m.mu.Unlock()
		return nil
	}
	ackCh := make(chan struct{}, 1)
	m.waiters[escalationID] = ackCh
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.waiters, escalationID)
		m.mu.Unlock()
	}()

	var timeoutCh <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		timeoutCh = t.C
	}

	select {
	case <-ackCh:
		return nil
	case <-timeoutCh:
		return &ackTimeoutError{msg: "escalation acknowledgment timed out"}
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *fakeEscalationManager) AcknowledgeEscalation(_ context.Context, id, by string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	esc, ok := m.escalations[id]
	if !ok {
		return &ackTimeoutError{msg: "not found"}
	}
	now := time.Now()
	esc.Acknowledged = true
	esc.AcknowledgedAt = &now
	esc.AcknowledgedBy = by
	m.escalations[id] = esc
	if ch, ok := m.waiters[id]; ok {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return nil
}

func (m *fakeEscalationManager) GetEscalations(_ context.Context, missionID string) ([]Escalation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Escalation{}
	for _, e := range m.escalations {
		if e.MissionID == missionID {
			out = append(out, e)
		}
	}
	return out, nil
}

type ackTimeoutError struct{ msg string }

func (e *ackTimeoutError) Error() string { return e.msg }

// TestEscalateAckTimeout — Spec 2 Task 15.
// Drives the escalation acknowledgment-wait path with an
// injected 100ms timeout and asserts the orchestrator handles
// the timeout cleanly without deadlocking, all within a
// 2-second wall-clock budget.
func TestEscalateAckTimeout(t *testing.T) {
	mgr := newFakeEscalationManager()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	id, err := mgr.CreateEscalation(ctx, Escalation{
		MissionID: "m1",
		NodeID:    "n1",
		Level:     "human",
		Urgency:   "critical",
		Context:   "test ack-timeout",
	})
	if err != nil {
		t.Fatalf("CreateEscalation: %v", err)
	}

	start := time.Now()
	err = mgr.WaitForAcknowledgment(ctx, id, 100*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error=%q want substring 'timed out'", err.Error())
	}
	if elapsed > 1*time.Second {
		t.Errorf("WaitForAcknowledgment elapsed=%v; expected ~100ms", elapsed)
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("WaitForAcknowledgment elapsed=%v; suspicious — timeout may not be wired", elapsed)
	}
}

// TestEscalateAckTimeout_ack_before_timeout — companion test
// asserting that acknowledging within the timeout window
// returns nil (no error) and that the wait unblocks promptly.
func TestEscalateAckTimeout_ack_before_timeout(t *testing.T) {
	mgr := newFakeEscalationManager()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	id, _ := mgr.CreateEscalation(ctx, Escalation{
		MissionID: "m1",
		NodeID:    "n1",
		Level:     "human",
		Urgency:   "critical",
		Context:   "test ack",
	})

	// Acknowledge from a goroutine after a short delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = mgr.AcknowledgeEscalation(ctx, id, "operator")
	}()

	start := time.Now()
	err := mgr.WaitForAcknowledgment(ctx, id, 1*time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("expected nil after ack, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("WaitForAcknowledgment elapsed=%v; expected to return ~50ms after ack", elapsed)
	}
}

// TestEscalateAckTimeout_non_critical_returns_immediately — for
// urgency != "critical", the manager returns nil immediately
// without blocking, so timeout doesn't apply.
func TestEscalateAckTimeout_non_critical_returns_immediately(t *testing.T) {
	mgr := newFakeEscalationManager()
	ctx := context.Background()
	id, _ := mgr.CreateEscalation(ctx, Escalation{
		MissionID: "m1",
		NodeID:    "n1",
		Urgency:   "high", // non-critical
	})
	start := time.Now()
	err := mgr.WaitForAcknowledgment(ctx, id, 5*time.Second)
	if err != nil {
		t.Errorf("non-critical: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Error("non-critical should return immediately, not block")
	}
}
