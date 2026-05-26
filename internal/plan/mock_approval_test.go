package plan

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestNewMockApprovalService(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		mock := NewMockApprovalService()
		if mock == nil {
			t.Fatal("expected non-nil mock service")
		}
		if mock.autoApprove {
			t.Error("expected autoApprove to be false by default")
		}
		if mock.autoDeny {
			t.Error("expected autoDeny to be false by default")
		}
		if mock.PendingCount() != 0 {
			t.Errorf("expected 0 pending requests, got %d", mock.PendingCount())
		}
	})

	t.Run("with auto approve", func(t *testing.T) {
		mock := NewMockApprovalService(WithAutoApprove())
		if !mock.autoApprove {
			t.Error("expected autoApprove to be true")
		}
		if mock.autoDeny {
			t.Error("expected autoDeny to be false when autoApprove is enabled")
		}
	})

	t.Run("with auto deny", func(t *testing.T) {
		reason := "security policy violation"
		mock := NewMockApprovalService(WithAutoDeny(reason))
		if mock.autoApprove {
			t.Error("expected autoApprove to be false when autoDeny is enabled")
		}
		if !mock.autoDeny {
			t.Error("expected autoDeny to be true")
		}
		if mock.denyReason != reason {
			t.Errorf("expected denyReason to be %q, got %q", reason, mock.denyReason)
		}
	})

	t.Run("with approval delay", func(t *testing.T) {
		delay := 200 * time.Millisecond
		mock := NewMockApprovalService(WithApprovalDelay(delay))
		if mock.approvalDelay != delay {
			t.Errorf("expected approvalDelay to be %v, got %v", delay, mock.approvalDelay)
		}
	})
}

func TestMockApprovalService_AutoApprove(t *testing.T) {
	mock := NewMockApprovalService(WithAutoApprove())
	ctx := context.Background()

	request := ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      types.NewID(),
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	decision, err := mock.RequestApproval(ctx, request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Approved {
		t.Error("expected auto-approved decision")
	}
	if decision.ApproverID != "mock-auto-approver" {
		t.Errorf("expected approver ID to be 'mock-auto-approver', got %q", decision.ApproverID)
	}

	// Verify request was moved from pending to decisions
	if mock.PendingCount() != 0 {
		t.Errorf("expected 0 pending requests after auto-approval, got %d", mock.PendingCount())
	}
}

func TestMockApprovalService_AutoDeny(t *testing.T) {
	reason := "test denial reason"
	mock := NewMockApprovalService(WithAutoDeny(reason))
	ctx := context.Background()

	request := ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      types.NewID(),
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	decision, err := mock.RequestApproval(ctx, request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Approved {
		t.Error("expected auto-denied decision")
	}
	if decision.Reason != reason {
		t.Errorf("expected denial reason to be %q, got %q", reason, decision.Reason)
	}
	if decision.ApproverID != "mock-auto-denier" {
		t.Errorf("expected approver ID to be 'mock-auto-denier', got %q", decision.ApproverID)
	}
}

func TestMockApprovalService_ManualApproval(t *testing.T) {
	mock := NewMockApprovalService()
	ctx := context.Background()

	request := ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      types.NewID(),
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	// Submit decision in a goroutine after delay
	decisionToSubmit := ApprovalDecision{
		Approved:   true,
		ApproverID: "test-user",
		Reason:     "looks good to me",
		DecidedAt:  time.Now(),
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		err := mock.SubmitDecision(ctx, request.ID, decisionToSubmit)
		if err != nil {
			t.Errorf("failed to submit decision: %v", err)
		}
	}()

	// Request approval - should block until decision is submitted
	decision, err := mock.RequestApproval(ctx, request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !decision.Approved {
		t.Error("expected approved decision")
	}
	if decision.ApproverID != "test-user" {
		t.Errorf("expected approver ID to be 'test-user', got %q", decision.ApproverID)
	}
	if decision.Reason != "looks good to me" {
		t.Errorf("expected reason to be 'looks good to me', got %q", decision.Reason)
	}
}

func TestMockApprovalService_ContextCancellation(t *testing.T) {
	mock := NewMockApprovalService()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	request := ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      types.NewID(),
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	// Request approval without submitting decision - should timeout
	_, err := mock.RequestApproval(ctx, request)
	if err == nil {
		t.Error("expected context timeout error")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestMockApprovalService_GetPendingApprovals(t *testing.T) {
	mock := NewMockApprovalService()
	ctx := context.Background()

	planID1 := types.NewID()
	planID2 := types.NewID()
	stepID1 := types.NewID()

	// Create several pending requests
	request1 := ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      planID1,
		StepID:      stepID1,
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	request2 := ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      planID1,
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	request3 := ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      planID2,
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	// Add requests to pending (simulate in-flight requests)
	mock.mu.Lock()
	mock.pendingRequests[request1.ID] = request1
	mock.pendingRequests[request2.ID] = request2
	mock.pendingRequests[request3.ID] = request3
	mock.mu.Unlock()

	t.Run("no filter", func(t *testing.T) {
		results, err := mock.GetPendingApprovals(ctx, ApprovalFilter{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 3 {
			t.Errorf("expected 3 pending approvals, got %d", len(results))
		}
	})

	t.Run("filter by plan ID", func(t *testing.T) {
		results, err := mock.GetPendingApprovals(ctx, ApprovalFilter{PlanID: &planID1})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 2 {
			t.Errorf("expected 2 pending approvals for planID1, got %d", len(results))
		}
	})

	t.Run("filter by step ID", func(t *testing.T) {
		results, err := mock.GetPendingApprovals(ctx, ApprovalFilter{StepID: &stepID1})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 1 {
			t.Errorf("expected 1 pending approval for stepID1, got %d", len(results))
		}
	})

	t.Run("filter by pending status", func(t *testing.T) {
		status := "pending"
		results, err := mock.GetPendingApprovals(ctx, ApprovalFilter{Status: &status})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 3 {
			t.Errorf("expected 3 pending approvals, got %d", len(results))
		}
	})

	t.Run("filter by non-pending status", func(t *testing.T) {
		status := "approved"
		results, err := mock.GetPendingApprovals(ctx, ApprovalFilter{Status: &status})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 0 {
			t.Errorf("expected 0 approvals with non-pending status, got %d", len(results))
		}
	})
}

func TestMockApprovalService_SubmitDecision(t *testing.T) {
	t.Run("successful submission", func(t *testing.T) {
		mock := NewMockApprovalService()
		ctx := context.Background()

		requestID := types.NewID()
		request := ApprovalRequest{
			ID:          requestID,
			PlanID:      types.NewID(),
			StepID:      types.NewID(),
			RequestedAt: time.Now(),
			ExpiresAt:   time.Now().Add(5 * time.Minute),
		}

		// Add to pending requests
		mock.mu.Lock()
		mock.pendingRequests[requestID] = request
		mock.mu.Unlock()

		decision := ApprovalDecision{
			Approved:   true,
			ApproverID: "test-user",
			Reason:     "approved",
			DecidedAt:  time.Now(),
		}

		err := mock.SubmitDecision(ctx, requestID, decision)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify request removed from pending
		if mock.PendingCount() != 0 {
			t.Errorf("expected 0 pending requests after submission, got %d", mock.PendingCount())
		}
	})

	t.Run("request not found", func(t *testing.T) {
		mock := NewMockApprovalService()
		ctx := context.Background()

		nonExistentID := types.NewID()
		decision := ApprovalDecision{
			Approved:   true,
			ApproverID: "test-user",
			DecidedAt:  time.Now(),
		}

		err := mock.SubmitDecision(ctx, nonExistentID, decision)
		if err == nil {
			t.Error("expected error for non-existent request ID")
		}
	})
}

func TestMockApprovalService_TestHelpers(t *testing.T) {
	t.Run("SetDecision", func(t *testing.T) {
		mock := NewMockApprovalService()
		requestID := types.NewID()

		decision := ApprovalDecision{
			Approved:   true,
			ApproverID: "test-helper",
			DecidedAt:  time.Now(),
		}

		mock.SetDecision(requestID, decision)

		// Verify decision was stored
		mock.mu.RLock()
		stored, exists := mock.decisions[requestID]
		mock.mu.RUnlock()

		if !exists {
			t.Fatal("expected decision to be stored")
		}
		if stored.ApproverID != "test-helper" {
			t.Errorf("expected approver ID to be 'test-helper', got %q", stored.ApproverID)
		}
	})

	t.Run("GetRequest", func(t *testing.T) {
		mock := NewMockApprovalService()
		requestID := types.NewID()

		request := ApprovalRequest{
			ID:     requestID,
			PlanID: types.NewID(),
			StepID: types.NewID(),
		}

		mock.mu.Lock()
		mock.pendingRequests[requestID] = request
		mock.mu.Unlock()

		retrieved, exists := mock.GetRequest(requestID)
		if !exists {
			t.Fatal("expected request to be found")
		}
		if retrieved.ID != requestID {
			t.Errorf("expected request ID to be %s, got %s", requestID, retrieved.ID)
		}

		// Test non-existent request
		nonExistentID := types.NewID()
		_, exists = mock.GetRequest(nonExistentID)
		if exists {
			t.Error("expected request to not be found")
		}
	})

	t.Run("ClearAll", func(t *testing.T) {
		mock := NewMockApprovalService()

		// Add some pending requests and decisions
		mock.mu.Lock()
		mock.pendingRequests[types.NewID()] = ApprovalRequest{}
		mock.pendingRequests[types.NewID()] = ApprovalRequest{}
		mock.decisions[types.NewID()] = ApprovalDecision{}
		mock.mu.Unlock()

		mock.ClearAll()

		if mock.PendingCount() != 0 {
			t.Errorf("expected 0 pending requests after ClearAll, got %d", mock.PendingCount())
		}

		mock.mu.RLock()
		decisionCount := len(mock.decisions)
		mock.mu.RUnlock()

		if decisionCount != 0 {
			t.Errorf("expected 0 decisions after ClearAll, got %d", decisionCount)
		}
	})

	t.Run("PendingCount", func(t *testing.T) {
		mock := NewMockApprovalService()

		if mock.PendingCount() != 0 {
			t.Errorf("expected 0 pending requests initially, got %d", mock.PendingCount())
		}

		mock.mu.Lock()
		mock.pendingRequests[types.NewID()] = ApprovalRequest{}
		mock.pendingRequests[types.NewID()] = ApprovalRequest{}
		mock.pendingRequests[types.NewID()] = ApprovalRequest{}
		mock.mu.Unlock()

		if mock.PendingCount() != 3 {
			t.Errorf("expected 3 pending requests, got %d", mock.PendingCount())
		}
	})
}

func TestMockApprovalService_ApprovalDelay(t *testing.T) {
	delay := 150 * time.Millisecond
	mock := NewMockApprovalService(WithAutoApprove(), WithApprovalDelay(delay))
	ctx := context.Background()

	request := ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      types.NewID(),
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	start := time.Now()
	_, err := mock.RequestApproval(ctx, request)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify delay was applied (with some tolerance for timing)
	if elapsed < delay {
		t.Errorf("expected delay of at least %v, got %v", delay, elapsed)
	}
}

func TestMockApprovalService_ConcurrentAccess(t *testing.T) {
	mock := NewMockApprovalService()
	ctx := context.Background()

	// Test concurrent approval requests and decision submissions
	const numRequests = 50

	errChan := make(chan error, numRequests*2)
	doneChan := make(chan bool)

	// Submit multiple approval requests concurrently
	for i := 0; i < numRequests; i++ {
		go func() {
			requestID := types.NewID()
			request := ApprovalRequest{
				ID:          requestID,
				PlanID:      types.NewID(),
				StepID:      types.NewID(),
				RequestedAt: time.Now(),
				ExpiresAt:   time.Now().Add(5 * time.Minute),
			}

			// Add to pending
			mock.mu.Lock()
			mock.pendingRequests[requestID] = request
			mock.mu.Unlock()

			// Submit decision after short delay
			decision := ApprovalDecision{
				Approved:   true,
				ApproverID: "concurrent-test",
				DecidedAt:  time.Now(),
			}

			time.Sleep(10 * time.Millisecond)
			if err := mock.SubmitDecision(ctx, requestID, decision); err != nil {
				errChan <- err
			}
		}()
	}

	// Wait for all goroutines with timeout
	go func() {
		time.Sleep(2 * time.Second)
		doneChan <- true
	}()

	select {
	case err := <-errChan:
		t.Fatalf("concurrent access error: %v", err)
	case <-doneChan:
		// Success - no errors
	}

	// Verify final state
	if mock.PendingCount() != 0 {
		t.Errorf("expected 0 pending requests after concurrent access, got %d", mock.PendingCount())
	}
}
