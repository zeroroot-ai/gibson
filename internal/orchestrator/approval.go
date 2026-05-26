package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/events"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// ApprovalRequest represents a request for human approval before continuing execution.
// These are created when the orchestrator encounters a request_approval decision action.
type ApprovalRequest struct {
	// ID is the unique identifier for this approval request
	ID string

	// MissionID is the mission this approval belongs to
	MissionID string

	// NodeID is the mission node that triggered the approval
	NodeID string

	// Context is a human-readable description of what needs approval
	Context string

	// RequestedAt is when the approval was requested
	RequestedAt time.Time

	// Timeout is how long to wait for approval before timing out
	Timeout time.Duration

	// TimeoutAction is what to do on timeout: "reject" or "skip"
	TimeoutAction string
}

// ApprovalResponse represents the response to an approval request.
type ApprovalResponse struct {
	// Approved indicates whether the request was approved (true) or rejected (false)
	Approved bool

	// RespondedAt is when the response was received
	RespondedAt time.Time

	// RespondedBy indicates who/what responded: "human", "timeout", "system"
	RespondedBy string

	// Comment is an optional comment explaining the decision
	Comment string
}

// ApprovalManager manages the lifecycle of approval requests.
// It stores approvals in Neo4j and uses channels to coordinate blocking waits.
type ApprovalManager interface {
	// CreateRequest creates a pending approval and returns its ID
	CreateRequest(ctx context.Context, req ApprovalRequest) (string, error)

	// WaitForApproval blocks until approval is granted, rejected, or times out
	WaitForApproval(ctx context.Context, approvalID string, timeout time.Duration) (ApprovalResponse, error)

	// RespondToApproval processes a human response (called externally)
	RespondToApproval(ctx context.Context, approvalID string, response ApprovalResponse) error

	// GetPendingApprovals lists all pending approvals for a mission
	GetPendingApprovals(ctx context.Context, missionID string) ([]ApprovalRequest, error)
}

// Neo4jApprovalManager implements ApprovalManager using Neo4j for storage.
// It uses channels for blocking wait coordination and is thread-safe.
type Neo4jApprovalManager struct {
	graphClient graph.GraphClient
	eventBus    EventBus

	// mu protects the waiters map
	mu sync.RWMutex

	// waiters maps approval IDs to response channels
	waiters map[string]chan ApprovalResponse
}

// NewNeo4jApprovalManager creates a new Neo4jApprovalManager.
func NewNeo4jApprovalManager(graphClient graph.GraphClient, eventBus EventBus) *Neo4jApprovalManager {
	return &Neo4jApprovalManager{
		graphClient: graphClient,
		eventBus:    eventBus,
		waiters:     make(map[string]chan ApprovalResponse),
	}
}

// CreateRequest creates a pending approval request in Neo4j and emits an event.
// Returns the approval ID.
func (m *Neo4jApprovalManager) CreateRequest(ctx context.Context, req ApprovalRequest) (string, error) {
	// Validate request
	if req.MissionID == "" {
		return "", types.NewError(graph.ErrCodeGraphInvalidQuery, "mission ID cannot be empty")
	}
	if req.NodeID == "" {
		return "", types.NewError(graph.ErrCodeGraphInvalidQuery, "node ID cannot be empty")
	}
	if req.Context == "" {
		return "", types.NewError(graph.ErrCodeGraphInvalidQuery, "context cannot be empty")
	}
	if req.TimeoutAction != "reject" && req.TimeoutAction != "skip" {
		return "", types.NewError(graph.ErrCodeGraphInvalidQuery, "timeout action must be 'reject' or 'skip'")
	}

	// Generate ID if not provided
	if req.ID == "" {
		id := types.NewID()
		req.ID = id.String()
	}

	// Set RequestedAt if not provided
	if req.RequestedAt.IsZero() {
		req.RequestedAt = time.Now()
	}

	// Create approval node in Neo4j
	cypher := `
		MATCH (m:Mission {id: $mission_id})
		MATCH (n:MissionNode {id: $node_id})
		CREATE (a:ApprovalRequest {
			id: $id,
			mission_id: $mission_id,
			node_id: $node_id,
			context: $context,
			requested_at: datetime($requested_at),
			timeout_duration_ms: $timeout_duration_ms,
			timeout_action: $timeout_action,
			status: 'pending'
		})
		CREATE (a)-[:FOR_NODE]->(n)
		CREATE (a)-[:PART_OF]->(m)
		RETURN a.id as id
	`

	params := map[string]any{
		"id":                  req.ID,
		"mission_id":          req.MissionID,
		"node_id":             req.NodeID,
		"context":             req.Context,
		"requested_at":        req.RequestedAt.UTC().Format(time.RFC3339Nano),
		"timeout_duration_ms": req.Timeout.Milliseconds(),
		"timeout_action":      req.TimeoutAction,
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return "", types.WrapError(graph.ErrCodeGraphNodeCreateFailed, "failed to create approval request", err)
	}

	if len(result.Records) == 0 {
		return "", types.NewError(graph.ErrCodeGraphNodeNotFound, "mission or node not found")
	}

	// Emit approval requested event
	if m.eventBus != nil {
		missionID, _ := types.ParseID(req.MissionID)
		m.eventBus.Publish(events.Event{
			Type:      events.EventApprovalRequested,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: map[string]any{
				"approval_id":    req.ID,
				"node_id":        req.NodeID,
				"context":        req.Context,
				"timeout_action": req.TimeoutAction,
			},
		})
	}

	return req.ID, nil
}

// WaitForApproval blocks until approval is granted, rejected, or times out.
// It uses channels and select for efficient blocking with timeout support.
func (m *Neo4jApprovalManager) WaitForApproval(ctx context.Context, approvalID string, timeout time.Duration) (ApprovalResponse, error) {
	if approvalID == "" {
		return ApprovalResponse{}, types.NewError(graph.ErrCodeGraphInvalidQuery, "approval ID cannot be empty")
	}

	// Create response channel for this approval
	responseCh := make(chan ApprovalResponse, 1)

	// Register the waiter
	m.mu.Lock()
	m.waiters[approvalID] = responseCh
	m.mu.Unlock()

	// Clean up waiter when done
	defer func() {
		m.mu.Lock()
		delete(m.waiters, approvalID)
		m.mu.Unlock()
		close(responseCh)
	}()

	// Wait for response, timeout, or context cancellation
	var timeoutTimer *time.Timer
	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timeoutTimer = time.NewTimer(timeout)
		timeoutCh = timeoutTimer.C
		defer timeoutTimer.Stop()
	}

	select {
	case response := <-responseCh:
		// Response received
		return response, nil

	case <-timeoutCh:
		// Timeout occurred
		return m.handleTimeout(ctx, approvalID)

	case <-ctx.Done():
		// Context cancelled
		return ApprovalResponse{}, ctx.Err()
	}
}

// handleTimeout handles approval timeout by applying the timeout action.
func (m *Neo4jApprovalManager) handleTimeout(ctx context.Context, approvalID string) (ApprovalResponse, error) {
	// Get the approval to check timeout action
	approval, err := m.getApproval(ctx, approvalID)
	if err != nil {
		return ApprovalResponse{}, types.WrapError(graph.ErrCodeGraphQueryFailed, "failed to get approval for timeout handling", err)
	}

	// Determine approved status based on timeout action
	approved := approval.TimeoutAction == "skip"

	response := ApprovalResponse{
		Approved:    approved,
		RespondedAt: time.Now(),
		RespondedBy: "timeout",
		Comment:     fmt.Sprintf("Approval timed out after %s, action: %s", approval.Timeout.String(), approval.TimeoutAction),
	}

	// Store timeout response in Neo4j
	if err := m.storeResponse(ctx, approvalID, response); err != nil {
		return ApprovalResponse{}, err
	}

	// Emit timeout event
	if m.eventBus != nil {
		missionID, _ := types.ParseID(approval.MissionID)
		m.eventBus.Publish(events.Event{
			Type:      events.EventApprovalTimeout,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: map[string]any{
				"approval_id":    approvalID,
				"timeout_action": approval.TimeoutAction,
				"approved":       approved,
			},
		})
	}

	return response, nil
}

// RespondToApproval processes a human response to an approval request.
// This is called externally (e.g., from a CLI command or web UI).
func (m *Neo4jApprovalManager) RespondToApproval(ctx context.Context, approvalID string, response ApprovalResponse) error {
	if approvalID == "" {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "approval ID cannot be empty")
	}

	// Set RespondedAt if not provided
	if response.RespondedAt.IsZero() {
		response.RespondedAt = time.Now()
	}

	// Set RespondedBy if not provided
	if response.RespondedBy == "" {
		response.RespondedBy = "human"
	}

	// Store response in Neo4j
	if err := m.storeResponse(ctx, approvalID, response); err != nil {
		return err
	}

	// Get approval for event emission
	approval, err := m.getApproval(ctx, approvalID)
	if err != nil {
		// Log warning but don't fail - response was stored
		return nil
	}

	// Emit appropriate event
	if m.eventBus != nil {
		missionID, _ := types.ParseID(approval.MissionID)
		eventType := events.EventApprovalRejected
		if response.Approved {
			eventType = events.EventApprovalGranted
		}

		m.eventBus.Publish(events.Event{
			Type:      eventType,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: map[string]any{
				"approval_id":  approvalID,
				"approved":     response.Approved,
				"responded_by": response.RespondedBy,
				"comment":      response.Comment,
			},
		})
	}

	// Notify any waiters
	m.mu.RLock()
	ch, exists := m.waiters[approvalID]
	m.mu.RUnlock()

	if exists {
		select {
		case ch <- response:
			// Response delivered
		default:
			// Channel full or closed, ignore
		}
	}

	return nil
}

// GetPendingApprovals retrieves all pending approvals for a mission.
func (m *Neo4jApprovalManager) GetPendingApprovals(ctx context.Context, missionID string) ([]ApprovalRequest, error) {
	if missionID == "" {
		return nil, types.NewError(graph.ErrCodeGraphInvalidQuery, "mission ID cannot be empty")
	}

	cypher := `
		MATCH (a:ApprovalRequest)-[:PART_OF]->(m:Mission {id: $mission_id})
		WHERE a.status = 'pending'
		RETURN properties(a) as a
		ORDER BY a.requested_at
	`

	params := map[string]any{
		"mission_id": missionID,
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return nil, types.WrapError(graph.ErrCodeGraphQueryFailed, "failed to query pending approvals", err)
	}

	approvals := make([]ApprovalRequest, 0, len(result.Records))
	for _, record := range result.Records {
		approval, err := recordToApprovalRequest(record["a"])
		if err != nil {
			return nil, fmt.Errorf("failed to parse approval request: %w", err)
		}
		approvals = append(approvals, approval)
	}

	return approvals, nil
}

// getApproval retrieves an approval request by ID.
func (m *Neo4jApprovalManager) getApproval(ctx context.Context, approvalID string) (ApprovalRequest, error) {
	cypher := `
		MATCH (a:ApprovalRequest {id: $approval_id})
		RETURN properties(a) as a
	`

	params := map[string]any{
		"approval_id": approvalID,
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return ApprovalRequest{}, err
	}

	if len(result.Records) == 0 {
		return ApprovalRequest{}, types.NewError(graph.ErrCodeGraphNodeNotFound, "approval request not found")
	}

	return recordToApprovalRequest(result.Records[0]["a"])
}

// storeResponse stores an approval response in Neo4j.
func (m *Neo4jApprovalManager) storeResponse(ctx context.Context, approvalID string, response ApprovalResponse) error {
	status := "rejected"
	if response.Approved {
		status = "approved"
	}

	cypher := `
		MATCH (a:ApprovalRequest {id: $approval_id})
		SET a.status = $status,
		    a.responded_at = datetime($responded_at),
		    a.responded_by = $responded_by,
		    a.comment = $comment
		RETURN a.id as id
	`

	params := map[string]any{
		"approval_id":  approvalID,
		"status":       status,
		"responded_at": response.RespondedAt.UTC().Format(time.RFC3339Nano),
		"responded_by": response.RespondedBy,
		"comment":      response.Comment,
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphQueryFailed, "failed to store approval response", err)
	}

	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeNotFound, "approval request not found")
	}

	return nil
}

// recordToApprovalRequest converts a Neo4j record to an ApprovalRequest.
func recordToApprovalRequest(data any) (ApprovalRequest, error) {
	a, ok := data.(map[string]any)
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("invalid approval request data type: %T", data)
	}

	id, ok := a["id"].(string)
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("missing or invalid approval ID")
	}

	missionID, ok := a["mission_id"].(string)
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("missing or invalid mission ID")
	}

	nodeID, ok := a["node_id"].(string)
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("missing or invalid node ID")
	}

	context, ok := a["context"].(string)
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("missing or invalid context")
	}

	timeoutAction, ok := a["timeout_action"].(string)
	if !ok {
		return ApprovalRequest{}, fmt.Errorf("missing or invalid timeout action")
	}

	approval := ApprovalRequest{
		ID:            id,
		MissionID:     missionID,
		NodeID:        nodeID,
		Context:       context,
		TimeoutAction: timeoutAction,
	}

	// Parse requested_at
	if requestedAt, ok := a["requested_at"].(time.Time); ok {
		approval.RequestedAt = requestedAt
	}

	// Parse timeout duration
	if timeoutMs, ok := a["timeout_duration_ms"]; ok {
		if ms, ok := toInt64(timeoutMs); ok {
			approval.Timeout = time.Duration(ms) * time.Millisecond
		}
	}

	return approval, nil
}

// ApprovalRequestPayload contains data for approval.requested events.
type ApprovalRequestPayload struct {
	ApprovalID    string `json:"approval_id"`
	MissionID     string `json:"mission_id"`
	NodeID        string `json:"node_id"`
	Context       string `json:"context"`
	TimeoutAction string `json:"timeout_action"`
}

// ApprovalResponsePayload contains data for approval.granted/rejected/timeout events.
type ApprovalResponsePayload struct {
	ApprovalID  string `json:"approval_id"`
	MissionID   string `json:"mission_id"`
	Approved    bool   `json:"approved"`
	RespondedBy string `json:"responded_by"`
	Comment     string `json:"comment,omitempty"`
}

// MarshalJSON implements json.Marshaler for ApprovalRequest.
func (r ApprovalRequest) MarshalJSON() ([]byte, error) {
	type Alias ApprovalRequest
	return json.Marshal(&struct {
		RequestedAt string `json:"requested_at"`
		Timeout     string `json:"timeout"`
		*Alias
	}{
		RequestedAt: r.RequestedAt.Format(time.RFC3339Nano),
		Timeout:     r.Timeout.String(),
		Alias:       (*Alias)(&r),
	})
}

// MarshalJSON implements json.Marshaler for ApprovalResponse.
func (r ApprovalResponse) MarshalJSON() ([]byte, error) {
	type Alias ApprovalResponse
	return json.Marshal(&struct {
		RespondedAt string `json:"responded_at"`
		*Alias
	}{
		RespondedAt: r.RespondedAt.Format(time.RFC3339Nano),
		Alias:       (*Alias)(&r),
	})
}
