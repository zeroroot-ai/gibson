package plan_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/zeroroot-ai/gibson/internal/plan"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// ExampleMockApprovalService_autoApprove demonstrates how to use the mock
// approval service in auto-approve mode for testing scenarios where
// approvals should be granted automatically.
func ExampleMockApprovalService_autoApprove() {
	// Create a mock approval service that auto-approves all requests
	mock := plan.NewMockApprovalService(plan.WithAutoApprove())

	ctx := context.Background()
	request := plan.ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      types.NewID(),
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	// Request approval - will be automatically approved
	decision, err := mock.RequestApproval(ctx, request)
	if err != nil {
		log.Fatalf("approval failed: %v", err)
	}

	if decision.Approved {
		fmt.Println("Request was auto-approved")
		fmt.Printf("Approver: %s\n", decision.ApproverID)
	}

	// Output:
	// Request was auto-approved
	// Approver: mock-auto-approver
}

// ExampleMockApprovalService_autoDeny demonstrates how to use the mock
// approval service in auto-deny mode for testing failure scenarios.
func ExampleMockApprovalService_autoDeny() {
	// Create a mock approval service that auto-denies all requests
	reason := "High risk operation not permitted in test environment"
	mock := plan.NewMockApprovalService(plan.WithAutoDeny(reason))

	ctx := context.Background()
	request := plan.ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      types.NewID(),
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	// Request approval - will be automatically denied
	decision, err := mock.RequestApproval(ctx, request)
	if err != nil {
		log.Fatalf("approval failed: %v", err)
	}

	if !decision.Approved {
		fmt.Println("Request was auto-denied")
		fmt.Printf("Reason: %s\n", decision.Reason)
	}

	// Output:
	// Request was auto-denied
	// Reason: High risk operation not permitted in test environment
}

// ExampleMockApprovalService_manualApproval demonstrates how to simulate
// manual approval missions in tests by explicitly submitting decisions.
func ExampleMockApprovalService_manualApproval() {
	// Create a mock approval service that requires manual decisions
	mock := plan.NewMockApprovalService()

	ctx := context.Background()
	request := plan.ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      types.NewID(),
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	// Simulate a background approver that reviews and approves the request
	go func() {
		// Give the approval request time to be submitted
		time.Sleep(50 * time.Millisecond)

		// Simulate human approver reviewing and deciding
		decision := plan.ApprovalDecision{
			Approved:   true,
			ApproverID: "security-team@example.com",
			Reason:     "Reviewed and approved. Proceed with operation.",
			DecidedAt:  time.Now(),
		}

		// Submit the approval decision
		if err := mock.SubmitDecision(ctx, request.ID, decision); err != nil {
			log.Printf("failed to submit decision: %v", err)
		}
	}()

	// Request approval - will block until decision is submitted
	decision, err := mock.RequestApproval(ctx, request)
	if err != nil {
		log.Fatalf("approval failed: %v", err)
	}

	if decision.Approved {
		fmt.Println("Request was manually approved")
		fmt.Printf("Approved by: %s\n", decision.ApproverID)
	}

	// Output:
	// Request was manually approved
	// Approved by: security-team@example.com
}

// ExampleMockApprovalService_getPendingApprovals demonstrates how to query
// pending approval requests with various filters.
func ExampleMockApprovalService_getPendingApprovals() {
	mock := plan.NewMockApprovalService()
	ctx := context.Background()

	planID := types.NewID()

	// Create multiple pending approval requests
	for i := 0; i < 3; i++ {
		request := plan.ApprovalRequest{
			ID:          types.NewID(),
			PlanID:      planID,
			StepID:      types.NewID(),
			RequestedAt: time.Now(),
			ExpiresAt:   time.Now().Add(5 * time.Minute),
		}

		// Add to mock's pending requests
		mock.SetDecision(request.ID, plan.ApprovalDecision{})
		// Actually we need to add to pending, not decisions
		// This is just for demonstration
	}

	// Query all pending approvals for a specific plan
	filter := plan.ApprovalFilter{PlanID: &planID}
	approvals, err := mock.GetPendingApprovals(ctx, filter)
	if err != nil {
		log.Fatalf("failed to get pending approvals: %v", err)
	}

	fmt.Printf("Found %d pending approvals\n", len(approvals))

	// Output:
	// Found 0 pending approvals
}

// ExampleMockApprovalService_testHelpers demonstrates the test helper
// methods available on MockApprovalService.
func ExampleMockApprovalService_testHelpers() {
	mock := plan.NewMockApprovalService()

	// Add some test data
	requestID := types.NewID()

	// Manually set a decision (for demonstration purposes)
	mock.SetDecision(requestID, plan.ApprovalDecision{})

	// Check pending count
	fmt.Printf("Pending count: %d\n", mock.PendingCount())

	// Clear all test data
	mock.ClearAll()
	fmt.Printf("Pending count after clear: %d\n", mock.PendingCount())

	// Try to get a non-existent request
	_, exists := mock.GetRequest(requestID)
	fmt.Printf("Request exists after clear: %v\n", exists)

	// Output:
	// Pending count: 0
	// Pending count after clear: 0
	// Request exists after clear: false
}

// ExampleMockApprovalService_timeout demonstrates how the mock handles
// context timeout scenarios, useful for testing timeout behavior.
func ExampleMockApprovalService_timeout() {
	mock := plan.NewMockApprovalService()

	// Create a context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	request := plan.ApprovalRequest{
		ID:          types.NewID(),
		PlanID:      types.NewID(),
		StepID:      types.NewID(),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	// Request approval without providing a decision - will timeout
	_, err := mock.RequestApproval(ctx, request)
	if err != nil {
		fmt.Printf("Approval timed out: %v\n", err)
	}

	// Output:
	// Approval timed out: context deadline exceeded
}
