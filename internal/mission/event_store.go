package mission

import (
	"context"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// EventStore provides persistence for mission events.
// Events are persisted for audit trail and replay capability.
type EventStore interface {
	// Append persists an event to the log.
	// This is synchronous and durable - the event is written to disk before returning.
	Append(ctx context.Context, event *MissionEvent) error

	// Query retrieves events matching filter criteria.
	// Results are ordered by created_at ascending.
	Query(ctx context.Context, filter *EventFilter) ([]*MissionEvent, error)

	// Stream returns a channel of events for a mission starting from a timestamp.
	// The channel is closed when all events are sent or context is cancelled.
	// This is useful for event replay during mission resume.
	Stream(ctx context.Context, missionID types.ID, fromTimestamp time.Time) (<-chan *MissionEvent, error)
}

// EventFilter provides filtering options for event queries.
type EventFilter struct {
	// MissionID filters events for a specific mission.
	MissionID *types.ID

	// EventTypes filters by event type (supports multiple types).
	EventTypes []MissionEventType

	// After filters events created after this time.
	After *time.Time

	// Before filters events created before this time.
	Before *time.Time

	// Limit limits the number of results.
	Limit int

	// Offset skips the first N results.
	Offset int
}

// NewEventFilter creates a new empty filter with default pagination.
func NewEventFilter() *EventFilter {
	return &EventFilter{
		Limit:  100,
		Offset: 0,
	}
}

// WithMissionID filters events for a specific mission.
func (f *EventFilter) WithMissionID(missionID types.ID) *EventFilter {
	f.MissionID = &missionID
	return f
}

// WithEventTypes filters by event types.
func (f *EventFilter) WithEventTypes(types ...MissionEventType) *EventFilter {
	f.EventTypes = types
	return f
}

// WithTimeRange filters by time range.
func (f *EventFilter) WithTimeRange(after, before time.Time) *EventFilter {
	f.After = &after
	f.Before = &before
	return f
}

// WithPagination sets pagination parameters.
func (f *EventFilter) WithPagination(limit, offset int) *EventFilter {
	f.Limit = limit
	f.Offset = offset
	return f
}
