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

// Escalation represents an escalation to a human or specialist agent.
// These are created when the orchestrator encounters an escalate decision action.
type Escalation struct {
	// ID is the unique identifier for this escalation
	ID string

	// MissionID is the mission this escalation belongs to
	MissionID string

	// NodeID is the mission node that triggered the escalation
	NodeID string

	// Level specifies who to escalate to: "human", "senior_agent", "specialist"
	Level string

	// Urgency specifies the escalation urgency: "critical", "high", "normal"
	Urgency string

	// Context is a human-readable description of what needs escalation
	Context string

	// CreatedAt is when the escalation was created
	CreatedAt time.Time

	// Acknowledged indicates whether the escalation has been acknowledged
	Acknowledged bool

	// AcknowledgedAt is when the escalation was acknowledged (nil if not acknowledged)
	AcknowledgedAt *time.Time

	// AcknowledgedBy indicates who acknowledged the escalation
	AcknowledgedBy string
}

// EscalationManager manages the lifecycle of escalations.
// It stores escalations in Neo4j and uses channels to coordinate blocking waits for critical escalations.
type EscalationManager interface {
	// CreateEscalation creates an escalation record and returns its ID
	CreateEscalation(ctx context.Context, esc Escalation) (string, error)

	// WaitForAcknowledgment blocks for critical escalations until acknowledged or timeout
	// Only blocks for escalations with urgency="critical", returns immediately for others
	WaitForAcknowledgment(ctx context.Context, escalationID string, timeout time.Duration) error

	// AcknowledgeEscalation processes an acknowledgment (called externally)
	AcknowledgeEscalation(ctx context.Context, escalationID string, acknowledgedBy string) error

	// GetEscalations lists all escalations for a mission
	GetEscalations(ctx context.Context, missionID string) ([]Escalation, error)
}

// Neo4jEscalationManager implements EscalationManager using Neo4j for storage.
// It uses channels for blocking wait coordination and is thread-safe.
type Neo4jEscalationManager struct {
	graphClient graph.GraphClient
	eventBus    EventBus

	// mu protects the waiters map
	mu sync.RWMutex

	// waiters maps escalation IDs to acknowledgment channels
	waiters map[string]chan struct{}
}

// NewNeo4jEscalationManager creates a new Neo4jEscalationManager.
func NewNeo4jEscalationManager(graphClient graph.GraphClient, eventBus EventBus) *Neo4jEscalationManager {
	return &Neo4jEscalationManager{
		graphClient: graphClient,
		eventBus:    eventBus,
		waiters:     make(map[string]chan struct{}),
	}
}

// CreateEscalation creates an escalation in Neo4j and emits an event.
// Returns the escalation ID.
func (m *Neo4jEscalationManager) CreateEscalation(ctx context.Context, esc Escalation) (string, error) {
	// Validate escalation
	if esc.MissionID == "" {
		return "", types.NewError(graph.ErrCodeGraphInvalidQuery, "mission ID cannot be empty")
	}
	if esc.NodeID == "" {
		return "", types.NewError(graph.ErrCodeGraphInvalidQuery, "node ID cannot be empty")
	}
	if esc.Level != "human" && esc.Level != "senior_agent" && esc.Level != "specialist" {
		return "", types.NewError(graph.ErrCodeGraphInvalidQuery, "level must be 'human', 'senior_agent', or 'specialist'")
	}
	if esc.Urgency != "critical" && esc.Urgency != "high" && esc.Urgency != "normal" {
		return "", types.NewError(graph.ErrCodeGraphInvalidQuery, "urgency must be 'critical', 'high', or 'normal'")
	}
	if esc.Context == "" {
		return "", types.NewError(graph.ErrCodeGraphInvalidQuery, "context cannot be empty")
	}

	// Generate ID if not provided
	if esc.ID == "" {
		id := types.NewID()
		esc.ID = id.String()
	}

	// Set CreatedAt if not provided
	if esc.CreatedAt.IsZero() {
		esc.CreatedAt = time.Now()
	}

	// Create escalation node in Neo4j
	cypher := `
		MATCH (m:Mission {id: $mission_id})
		MATCH (n:MissionNode {id: $node_id})
		CREATE (e:Escalation {
			id: $id,
			mission_id: $mission_id,
			node_id: $node_id,
			level: $level,
			urgency: $urgency,
			context: $context,
			created_at: datetime($created_at),
			acknowledged: false
		})
		CREATE (e)-[:FOR_NODE]->(n)
		CREATE (e)-[:PART_OF]->(m)
		RETURN e.id as id
	`

	params := map[string]any{
		"id":         esc.ID,
		"mission_id": esc.MissionID,
		"node_id":    esc.NodeID,
		"level":      esc.Level,
		"urgency":    esc.Urgency,
		"context":    esc.Context,
		"created_at": esc.CreatedAt.UTC().Format(time.RFC3339Nano),
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return "", types.WrapError(graph.ErrCodeGraphNodeCreateFailed, "failed to create escalation", err)
	}

	if len(result.Records) == 0 {
		return "", types.NewError(graph.ErrCodeGraphNodeNotFound, "mission or node not found")
	}

	// Emit escalation created event
	if m.eventBus != nil {
		missionID, _ := types.ParseID(esc.MissionID)
		m.eventBus.Publish(events.Event{
			Type:      events.EventEscalationCreated,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: map[string]any{
				"escalation_id": esc.ID,
				"node_id":       esc.NodeID,
				"level":         esc.Level,
				"urgency":       esc.Urgency,
				"context":       esc.Context,
			},
		})
	}

	return esc.ID, nil
}

// WaitForAcknowledgment blocks for critical escalations until acknowledged or timeout.
// For non-critical escalations (urgency != "critical"), returns immediately.
func (m *Neo4jEscalationManager) WaitForAcknowledgment(ctx context.Context, escalationID string, timeout time.Duration) error {
	if escalationID == "" {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "escalation ID cannot be empty")
	}

	// Get escalation to check urgency
	escalation, err := m.getEscalation(ctx, escalationID)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphQueryFailed, "failed to get escalation", err)
	}

	// Only block for critical escalations
	if escalation.Urgency != "critical" {
		return nil
	}

	// Create acknowledgment channel for this escalation
	ackCh := make(chan struct{}, 1)

	// Register the waiter
	m.mu.Lock()
	m.waiters[escalationID] = ackCh
	m.mu.Unlock()

	// Clean up waiter when done
	defer func() {
		m.mu.Lock()
		delete(m.waiters, escalationID)
		m.mu.Unlock()
		close(ackCh)
	}()

	// Wait for acknowledgment, timeout, or context cancellation
	var timeoutTimer *time.Timer
	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timeoutTimer = time.NewTimer(timeout)
		timeoutCh = timeoutTimer.C
		defer timeoutTimer.Stop()
	}

	select {
	case <-ackCh:
		// Acknowledgment received
		return nil

	case <-timeoutCh:
		// Timeout occurred
		return types.NewError(graph.ErrCodeGraphQueryFailed, "escalation acknowledgment timed out")

	case <-ctx.Done():
		// Context cancelled
		return ctx.Err()
	}
}

// AcknowledgeEscalation processes an acknowledgment of an escalation.
// This is called externally (e.g., from a CLI command or web UI).
func (m *Neo4jEscalationManager) AcknowledgeEscalation(ctx context.Context, escalationID string, acknowledgedBy string) error {
	if escalationID == "" {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "escalation ID cannot be empty")
	}
	if acknowledgedBy == "" {
		acknowledgedBy = "system"
	}

	acknowledgedAt := time.Now()

	// Update escalation in Neo4j
	cypher := `
		MATCH (e:Escalation {id: $escalation_id})
		SET e.acknowledged = true,
		    e.acknowledged_at = datetime($acknowledged_at),
		    e.acknowledged_by = $acknowledged_by
		RETURN e.id as id, e.mission_id as mission_id
	`

	params := map[string]any{
		"escalation_id":   escalationID,
		"acknowledged_at": acknowledgedAt.UTC().Format(time.RFC3339Nano),
		"acknowledged_by": acknowledgedBy,
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphQueryFailed, "failed to acknowledge escalation", err)
	}

	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeNotFound, "escalation not found")
	}

	// Get mission ID for event
	var missionID types.ID
	if missionIDStr, ok := result.Records[0]["mission_id"].(string); ok {
		missionID, _ = types.ParseID(missionIDStr)
	}

	// Emit escalation acknowledged event
	if m.eventBus != nil {
		m.eventBus.Publish(events.Event{
			Type:      events.EventEscalationAcknowledged,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: map[string]any{
				"escalation_id":   escalationID,
				"acknowledged_by": acknowledgedBy,
				"acknowledged_at": acknowledgedAt.Format(time.RFC3339Nano),
			},
		})
	}

	// Notify any waiters
	m.mu.RLock()
	ch, exists := m.waiters[escalationID]
	m.mu.RUnlock()

	if exists {
		select {
		case ch <- struct{}{}:
			// Acknowledgment signal delivered
		default:
			// Channel full or closed, ignore
		}
	}

	return nil
}

// GetEscalations retrieves all escalations for a mission, ordered by creation time.
func (m *Neo4jEscalationManager) GetEscalations(ctx context.Context, missionID string) ([]Escalation, error) {
	if missionID == "" {
		return nil, types.NewError(graph.ErrCodeGraphInvalidQuery, "mission ID cannot be empty")
	}

	cypher := `
		MATCH (e:Escalation)-[:PART_OF]->(m:Mission {id: $mission_id})
		RETURN properties(e) as e
		ORDER BY e.created_at
	`

	params := map[string]any{
		"mission_id": missionID,
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return nil, types.WrapError(graph.ErrCodeGraphQueryFailed, "failed to query escalations", err)
	}

	escalations := make([]Escalation, 0, len(result.Records))
	for _, record := range result.Records {
		escalation, err := recordToEscalation(record["e"])
		if err != nil {
			return nil, fmt.Errorf("failed to parse escalation: %w", err)
		}
		escalations = append(escalations, escalation)
	}

	return escalations, nil
}

// getEscalation retrieves an escalation by ID.
func (m *Neo4jEscalationManager) getEscalation(ctx context.Context, escalationID string) (Escalation, error) {
	cypher := `
		MATCH (e:Escalation {id: $escalation_id})
		RETURN properties(e) as e
	`

	params := map[string]any{
		"escalation_id": escalationID,
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return Escalation{}, err
	}

	if len(result.Records) == 0 {
		return Escalation{}, types.NewError(graph.ErrCodeGraphNodeNotFound, "escalation not found")
	}

	return recordToEscalation(result.Records[0]["e"])
}

// recordToEscalation converts a Neo4j record to an Escalation.
func recordToEscalation(data any) (Escalation, error) {
	e, ok := data.(map[string]any)
	if !ok {
		return Escalation{}, fmt.Errorf("invalid escalation data type: %T", data)
	}

	id, ok := e["id"].(string)
	if !ok {
		return Escalation{}, fmt.Errorf("missing or invalid escalation ID")
	}

	missionID, ok := e["mission_id"].(string)
	if !ok {
		return Escalation{}, fmt.Errorf("missing or invalid mission ID")
	}

	nodeID, ok := e["node_id"].(string)
	if !ok {
		return Escalation{}, fmt.Errorf("missing or invalid node ID")
	}

	level, ok := e["level"].(string)
	if !ok {
		return Escalation{}, fmt.Errorf("missing or invalid level")
	}

	urgency, ok := e["urgency"].(string)
	if !ok {
		return Escalation{}, fmt.Errorf("missing or invalid urgency")
	}

	context, ok := e["context"].(string)
	if !ok {
		return Escalation{}, fmt.Errorf("missing or invalid context")
	}

	escalation := Escalation{
		ID:        id,
		MissionID: missionID,
		NodeID:    nodeID,
		Level:     level,
		Urgency:   urgency,
		Context:   context,
	}

	// Parse created_at
	if createdAt, ok := e["created_at"].(time.Time); ok {
		escalation.CreatedAt = createdAt
	}

	// Parse acknowledged
	if acknowledged, ok := e["acknowledged"].(bool); ok {
		escalation.Acknowledged = acknowledged
	}

	// Parse acknowledged_at
	if acknowledgedAt, ok := e["acknowledged_at"].(time.Time); ok {
		escalation.AcknowledgedAt = &acknowledgedAt
	}

	// Parse acknowledged_by
	if acknowledgedBy, ok := e["acknowledged_by"].(string); ok {
		escalation.AcknowledgedBy = acknowledgedBy
	}

	return escalation, nil
}

// EscalationCreatedPayload contains data for escalation.created events.
type EscalationCreatedPayload struct {
	EscalationID string `json:"escalation_id"`
	MissionID    string `json:"mission_id"`
	NodeID       string `json:"node_id"`
	Level        string `json:"level"`
	Urgency      string `json:"urgency"`
	Context      string `json:"context"`
}

// EscalationAcknowledgedPayload contains data for escalation.acknowledged events.
type EscalationAcknowledgedPayload struct {
	EscalationID   string `json:"escalation_id"`
	MissionID      string `json:"mission_id"`
	AcknowledgedBy string `json:"acknowledged_by"`
	AcknowledgedAt string `json:"acknowledged_at"`
}

// MarshalJSON implements json.Marshaler for Escalation.
func (e Escalation) MarshalJSON() ([]byte, error) {
	type Alias Escalation

	var acknowledgedAtStr string
	if e.AcknowledgedAt != nil {
		acknowledgedAtStr = e.AcknowledgedAt.Format(time.RFC3339Nano)
	}

	return json.Marshal(&struct {
		CreatedAt      string  `json:"created_at"`
		AcknowledgedAt *string `json:"acknowledged_at,omitempty"`
		*Alias
	}{
		CreatedAt: e.CreatedAt.Format(time.RFC3339Nano),
		AcknowledgedAt: func() *string {
			if acknowledgedAtStr != "" {
				return &acknowledgedAtStr
			}
			return nil
		}(),
		Alias: (*Alias)(&e),
	})
}
