package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/types"
)

// EventBus manages event distribution to subscribers.
// It supports filtering by event type and mission ID.
//
// The event bus is thread-safe and supports multiple concurrent subscribers.
// Slow consumers are handled gracefully - if a subscriber's channel is full,
// the event is dropped for that subscriber to prevent blocking others.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[string]*subscription
	bufferSize  int
	logger      *slog.Logger
	closed      bool
}

// subscription represents a single client subscription with filtering.
type subscription struct {
	id         string
	ch         chan api.EventData
	eventTypes map[string]bool // Empty means all event types
	missionID  string          // Empty means all missions
	ctx        context.Context
	cancel     context.CancelFunc
}

// EventBusOption is a functional option for configuring EventBus.
type EventBusOption func(*EventBus)

// WithEventBufferSize sets the buffer size for subscriber channels.
// Default is 100. Larger buffers can handle bursty events better.
func WithEventBufferSize(size int) EventBusOption {
	return func(eb *EventBus) {
		eb.bufferSize = size
	}
}

// NewEventBus creates a new event bus for distributing daemon events.
//
// The event bus supports filtering by event type and mission ID.
// Subscribers receive events through buffered channels.
//
// Parameters:
//   - logger: Structured logger for event bus operations
//   - opts: Optional configuration options
//
// Returns:
//   - *EventBus: A new event bus ready to accept subscriptions
func NewEventBus(logger *slog.Logger, opts ...EventBusOption) *EventBus {
	if logger == nil {
		logger = slog.Default().With("component", "eventbus")
	}

	eb := &EventBus{
		subscribers: make(map[string]*subscription),
		bufferSize:  100, // Default buffer size
		logger:      logger.With("component", "eventbus"),
		closed:      false,
	}

	for _, opt := range opts {
		opt(eb)
	}

	return eb
}

// Publish sends an event to all matching subscribers.
//
// Events are filtered based on subscriber preferences:
//   - If subscriber specified event types, only matching types are sent
//   - If subscriber specified a mission ID, only events for that mission are sent
//
// If a subscriber's channel is full, the event is dropped for that subscriber
// to prevent blocking other subscribers (slow consumer handling).
//
// Parameters:
//   - ctx: Context for the publish operation
//   - event: The event to publish
//
// Returns:
//   - error: Non-nil if the event bus is closed
func (eb *EventBus) Publish(ctx context.Context, event api.EventData) error {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if eb.closed {
		return fmt.Errorf("event bus is closed")
	}

	// Track how many subscribers received the event
	sent := 0
	dropped := 0

	// Send to all matching subscribers
	for _, sub := range eb.subscribers {
		// Check if subscription context is cancelled
		select {
		case <-sub.ctx.Done():
			// Subscriber disconnected, will be cleaned up by unsubscribe
			continue
		default:
		}

		// Filter by event type
		if len(sub.eventTypes) > 0 && !sub.eventTypes[event.EventType] {
			continue
		}

		// Filter by mission ID if applicable
		if sub.missionID != "" {
			// Check if event has a mission ID
			missionID := extractMissionID(event)
			if missionID != "" && missionID != sub.missionID {
				continue
			}
		}

		// Try to send event (non-blocking)
		select {
		case sub.ch <- event:
			sent++
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Channel is full, drop event for this slow subscriber
			dropped++
			eb.logger.Warn("dropped event for slow subscriber",
				"subscriber_id", sub.id,
				"event_type", event.EventType,
			)
		}
	}

	if sent > 0 || dropped > 0 {
		eb.logger.Debug("published event",
			"event_type", event.EventType,
			"sent", sent,
			"dropped", dropped,
		)
	}

	return nil
}

// Subscribe creates a new subscription with filtering options.
//
// The returned channel will receive events matching the filter criteria.
// The caller must call the cleanup function to unsubscribe and prevent leaks.
//
// Parameters:
//   - ctx: Context for the subscription lifetime
//   - eventTypes: List of event types to receive (empty = all)
//   - missionID: Mission ID to filter by (empty = all)
//
// Returns:
//   - <-chan api.EventData: Channel that will receive matching events
//   - func(): Cleanup function to unsubscribe (must be called)
func (eb *EventBus) Subscribe(ctx context.Context, eventTypes []string, missionID string) (<-chan api.EventData, func()) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// Generate unique subscriber ID
	subscriberID := types.NewID().String()

	// Create subscription context that inherits from parent
	subCtx, cancel := context.WithCancel(ctx)

	// Convert event types to map for O(1) lookup
	eventTypeMap := make(map[string]bool)
	for _, et := range eventTypes {
		eventTypeMap[et] = true
	}

	// Create subscription
	sub := &subscription{
		id:         subscriberID,
		ch:         make(chan api.EventData, eb.bufferSize),
		eventTypes: eventTypeMap,
		missionID:  missionID,
		ctx:        subCtx,
		cancel:     cancel,
	}

	eb.subscribers[subscriberID] = sub

	eb.logger.Info("new subscription created",
		"subscriber_id", subscriberID,
		"event_types", eventTypes,
		"mission_id", missionID,
	)

	// Cleanup function to unsubscribe
	cleanup := func() {
		eb.unsubscribe(subscriberID)
	}

	return sub.ch, cleanup
}

// unsubscribe removes a subscription and closes its channel.
func (eb *EventBus) unsubscribe(subscriberID string) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	sub, exists := eb.subscribers[subscriberID]
	if !exists {
		return
	}

	// Cancel subscription context
	sub.cancel()

	// Close channel and remove from map
	close(sub.ch)
	delete(eb.subscribers, subscriberID)

	eb.logger.Info("subscription removed", "subscriber_id", subscriberID)
}

// Close shuts down the event bus and closes all subscriber channels.
func (eb *EventBus) Close() error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.closed {
		return nil
	}

	eb.closed = true

	// Close all subscriber channels
	for id, sub := range eb.subscribers {
		sub.cancel()
		close(sub.ch)
		delete(eb.subscribers, id)
	}

	eb.logger.Info("event bus closed")
	return nil
}

// SubscriberCount returns the current number of active subscribers.
// Useful for monitoring and testing.
func (eb *EventBus) SubscriberCount() int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.subscribers)
}

// extractMissionID extracts the mission ID from an event if present.
func extractMissionID(event api.EventData) string {
	// Check specific event types
	if event.MissionEvent != nil {
		return event.MissionEvent.MissionID
	}
	if event.FindingEvent != nil {
		return event.FindingEvent.MissionID
	}
	// No mission ID in this event
	return ""
}

// Helper functions to create events

// NewMissionStartedEvent creates a mission started event.
func NewMissionStartedEvent(missionID string) api.EventData {
	return api.EventData{
		EventType: "mission.started",
		Timestamp: time.Now(),
		Source:    "daemon",
		MissionEvent: &api.MissionEventData{
			EventType: "mission.started",
			Timestamp: time.Now(),
			MissionID: missionID,
			Message:   "Mission started",
		},
	}
}

// NewMissionCompletedEvent creates a mission completed event.
func NewMissionCompletedEvent(missionID string) api.EventData {
	return api.EventData{
		EventType: "mission.completed",
		Timestamp: time.Now(),
		Source:    "daemon",
		MissionEvent: &api.MissionEventData{
			EventType: "mission.completed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Message:   "Mission completed",
		},
	}
}

// NewMissionFailedEvent creates a mission failed event.
func NewMissionFailedEvent(missionID string, err error) api.EventData {
	return api.EventData{
		EventType: "mission.failed",
		Timestamp: time.Now(),
		Source:    "daemon",
		MissionEvent: &api.MissionEventData{
			EventType: "mission.failed",
			Timestamp: time.Now(),
			MissionID: missionID,
			Message:   "Mission failed",
			Error:     err.Error(),
		},
	}
}

// NewNodeStartedEvent creates a node started event.
func NewNodeStartedEvent(missionID, nodeID string) api.EventData {
	return api.EventData{
		EventType: "node.started",
		Timestamp: time.Now(),
		Source:    "daemon",
		MissionEvent: &api.MissionEventData{
			EventType: "node.started",
			Timestamp: time.Now(),
			MissionID: missionID,
			NodeID:    nodeID,
			Message:   "Node started",
		},
	}
}

// NewNodeCompletedEvent creates a node completed event.
func NewNodeCompletedEvent(missionID, nodeID string) api.EventData {
	return api.EventData{
		EventType: "node.completed",
		Timestamp: time.Now(),
		Source:    "daemon",
		MissionEvent: &api.MissionEventData{
			EventType: "node.completed",
			Timestamp: time.Now(),
			MissionID: missionID,
			NodeID:    nodeID,
			Message:   "Node completed",
		},
	}
}

// NewFindingDiscoveredEvent creates a finding discovered event.
func NewFindingDiscoveredEvent(missionID string, finding api.FindingData) api.EventData {
	return api.EventData{
		EventType: "finding.discovered",
		Timestamp: time.Now(),
		Source:    "daemon",
		FindingEvent: &api.FindingEventData{
			EventType: "finding.discovered",
			Timestamp: time.Now(),
			Finding:   finding,
			MissionID: missionID,
		},
	}
}

// NewAgentRegisteredEvent creates an agent registered event.
func NewAgentRegisteredEvent(agentID, agentName string) api.EventData {
	return api.EventData{
		EventType: "agent.registered",
		Timestamp: time.Now(),
		Source:    "daemon",
		AgentEvent: &api.AgentEventData{
			EventType: "agent.registered",
			Timestamp: time.Now(),
			AgentID:   agentID,
			AgentName: agentName,
			Message:   "Agent registered",
		},
	}
}

// NewAgentUnregisteredEvent creates an agent unregistered event.
func NewAgentUnregisteredEvent(agentID, agentName string) api.EventData {
	return api.EventData{
		EventType: "agent.unregistered",
		Timestamp: time.Now(),
		Source:    "daemon",
		AgentEvent: &api.AgentEventData{
			EventType: "agent.unregistered",
			Timestamp: time.Now(),
			AgentID:   agentID,
			AgentName: agentName,
			Message:   "Agent unregistered",
		},
	}
}
