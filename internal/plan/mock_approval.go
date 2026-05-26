package plan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// MockApprovalService is a test implementation of ApprovalService that provides
// configurable behavior for testing approval missions without requiring real
// human interaction or external services.
type MockApprovalService struct {
	mu              sync.RWMutex
	autoApprove     bool
	autoDeny        bool
	denyReason      string
	approvalDelay   time.Duration
	pendingRequests map[types.ID]ApprovalRequest
	decisions       map[types.ID]ApprovalDecision
}

// Verify MockApprovalService implements ApprovalService interface
var _ ApprovalService = (*MockApprovalService)(nil)

// MockApprovalOption is a functional option for configuring MockApprovalService behavior.
type MockApprovalOption func(*MockApprovalService)

// WithAutoApprove configures the mock to automatically approve all requests
// immediately without requiring explicit decision submission.
func WithAutoApprove() MockApprovalOption {
	return func(m *MockApprovalService) {
		m.autoApprove = true
		m.autoDeny = false
	}
}

// WithAutoDeny configures the mock to automatically deny all requests
// with the provided reason.
func WithAutoDeny(reason string) MockApprovalOption {
	return func(m *MockApprovalService) {
		m.autoDeny = true
		m.autoApprove = false
		m.denyReason = reason
	}
}

// WithApprovalDelay adds a delay before returning approval decisions.
// Useful for testing timeout behavior and concurrent access patterns.
func WithApprovalDelay(d time.Duration) MockApprovalOption {
	return func(m *MockApprovalService) {
		m.approvalDelay = d
	}
}

// NewMockApprovalService creates a new mock approval service with the specified options.
// By default, the mock requires explicit decision submission via SubmitDecision.
func NewMockApprovalService(opts ...MockApprovalOption) *MockApprovalService {
	m := &MockApprovalService{
		pendingRequests: make(map[types.ID]ApprovalRequest),
		decisions:       make(map[types.ID]ApprovalDecision),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// RequestApproval submits a new approval request and waits for a decision.
// Behavior depends on configuration:
//   - If autoApprove is set, returns immediate approval
//   - If autoDeny is set, returns immediate denial with configured reason
//   - Otherwise, waits for decision via SubmitDecision or context cancellation
//   - If approvalDelay is configured, sleeps before returning
func (m *MockApprovalService) RequestApproval(ctx context.Context, request ApprovalRequest) (ApprovalDecision, error) {
	m.mu.Lock()
	m.pendingRequests[request.ID] = request
	m.mu.Unlock()

	// Apply configured delay if set
	if m.approvalDelay > 0 {
		select {
		case <-time.After(m.approvalDelay):
			// Delay completed
		case <-ctx.Done():
			return ApprovalDecision{}, ctx.Err()
		}
	}

	// Handle auto-approval mode
	if m.autoApprove {
		decision := ApprovalDecision{
			Approved:   true,
			ApproverID: "mock-auto-approver",
			Reason:     "Auto-approved by mock service",
			DecidedAt:  time.Now(),
		}

		m.mu.Lock()
		delete(m.pendingRequests, request.ID)
		m.decisions[request.ID] = decision
		m.mu.Unlock()

		return decision, nil
	}

	// Handle auto-deny mode
	if m.autoDeny {
		decision := ApprovalDecision{
			Approved:   false,
			ApproverID: "mock-auto-denier",
			Reason:     m.denyReason,
			DecidedAt:  time.Now(),
		}

		m.mu.Lock()
		delete(m.pendingRequests, request.ID)
		m.decisions[request.ID] = decision
		m.mu.Unlock()

		return decision, nil
	}

	// Wait for explicit decision submission
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ApprovalDecision{}, ctx.Err()
		case <-ticker.C:
			m.mu.RLock()
			decision, exists := m.decisions[request.ID]
			m.mu.RUnlock()

			if exists {
				return decision, nil
			}
		}
	}
}

// GetPendingApprovals retrieves all approval requests matching the filter criteria.
// Returns a list of pending approval requests that await decisions.
func (m *MockApprovalService) GetPendingApprovals(ctx context.Context, filter ApprovalFilter) ([]ApprovalRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []ApprovalRequest

	for _, request := range m.pendingRequests {
		// Apply PlanID filter if specified
		if filter.PlanID != nil && request.PlanID != *filter.PlanID {
			continue
		}

		// Apply StepID filter if specified
		if filter.StepID != nil && request.StepID != *filter.StepID {
			continue
		}

		// Status filter is always "pending" for requests in pendingRequests map
		// If status filter is set to something other than "pending", skip
		if filter.Status != nil && *filter.Status != "pending" {
			continue
		}

		results = append(results, request)
	}

	return results, nil
}

// SubmitDecision records an approval decision for a specific request.
// The requestID must match an existing pending approval request.
// Returns an error if the request ID is not found in pending requests.
func (m *MockApprovalService) SubmitDecision(ctx context.Context, requestID types.ID, decision ApprovalDecision) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Verify the request exists
	if _, exists := m.pendingRequests[requestID]; !exists {
		return fmt.Errorf("approval request not found: %s", requestID)
	}

	// Store the decision and remove from pending
	m.decisions[requestID] = decision
	delete(m.pendingRequests, requestID)

	return nil
}

// Test helper methods

// SetDecision directly sets a decision for a request ID without validation.
// This is a test helper that bypasses normal mission for setting up test scenarios.
func (m *MockApprovalService) SetDecision(requestID types.ID, decision ApprovalDecision) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.decisions[requestID] = decision
	delete(m.pendingRequests, requestID)
}

// GetRequest retrieves a pending approval request by ID.
// Returns the request and true if found, or an empty request and false if not found.
func (m *MockApprovalService) GetRequest(requestID types.ID) (ApprovalRequest, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	request, exists := m.pendingRequests[requestID]
	return request, exists
}

// ClearAll removes all pending requests and decisions.
// Useful for resetting state between test cases.
func (m *MockApprovalService) ClearAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pendingRequests = make(map[types.ID]ApprovalRequest)
	m.decisions = make(map[types.ID]ApprovalDecision)
}

// PendingCount returns the number of pending approval requests.
// Useful for test assertions about mission state.
func (m *MockApprovalService) PendingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.pendingRequests)
}
