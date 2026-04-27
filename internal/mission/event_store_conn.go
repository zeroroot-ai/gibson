// Package mission — event_store_conn.go
//
// ConnBoundEventStore implements EventStore using a tenant-bound *redis.Client.
// No key prefixes are used; tenant isolation is structural (audit C7/C10 closure).
package mission

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ConnBoundEventStore implements EventStore against a tenant-bound Redis client.
// Keys carry no tenant prefix — the per-tenant client is the isolation boundary.
type ConnBoundEventStore struct {
	rdb *goredis.Client
}

// NewConnBoundEventStore creates an EventStore backed by the given tenant-bound client.
func NewConnBoundEventStore(rdb *goredis.Client) *ConnBoundEventStore {
	return &ConnBoundEventStore{rdb: rdb}
}

// connStreamKey returns the Redis Stream key for a mission's events.
func connStreamKey(missionID types.ID) string {
	return fmt.Sprintf("gibson:stream:mission:%s:events", missionID)
}

// Append persists an event to the Redis Stream.
func (s *ConnBoundEventStore) Append(ctx context.Context, event *MissionEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	var payloadJSON string
	if event.Payload != nil {
		data, err := json.Marshal(event.Payload)
		if err != nil {
			return fmt.Errorf("failed to marshal event payload: %w", err)
		}
		payloadJSON = string(data)
	}
	values := map[string]any{
		"event_type": string(event.Type),
		"payload":    payloadJSON,
		"created_at": ts.Format(time.RFC3339Nano),
	}
	if _, err := s.rdb.XAdd(ctx, &goredis.XAddArgs{
		Stream: connStreamKey(event.MissionID),
		Values: values,
	}).Result(); err != nil {
		return fmt.Errorf("failed to append event: %w", err)
	}
	return nil
}

// Query retrieves events matching the filter criteria.
func (s *ConnBoundEventStore) Query(ctx context.Context, filter *EventFilter) ([]*MissionEvent, error) {
	if filter == nil {
		filter = NewEventFilter()
	}
	if filter.Limit == 0 {
		filter.Limit = 100
	}
	if filter.MissionID == nil {
		return nil, fmt.Errorf("mission ID is required for event query")
	}

	missionID := *filter.MissionID
	msgs, err := s.rdb.XRange(ctx, connStreamKey(missionID), "-", "+").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to read events: %w", err)
	}

	events := make([]*MissionEvent, 0, len(msgs))
	for _, msg := range msgs {
		event, err := parseXMessage(msg, missionID)
		if err != nil {
			continue
		}
		if len(filter.EventTypes) > 0 {
			matched := false
			for _, et := range filter.EventTypes {
				if event.Type == et {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if filter.After != nil && event.Timestamp.Before(*filter.After) {
			continue
		}
		if filter.Before != nil && event.Timestamp.After(*filter.Before) {
			continue
		}
		events = append(events, event)
	}

	start := filter.Offset
	if start > len(events) {
		start = len(events)
	}
	end := start + filter.Limit
	if end > len(events) {
		end = len(events)
	}
	return events[start:end], nil
}

// Stream returns a channel of events starting from fromTimestamp.
func (s *ConnBoundEventStore) Stream(ctx context.Context, missionID types.ID, fromTimestamp time.Time) (<-chan *MissionEvent, error) {
	// Fetch historical events first.
	allMsgs, err := s.rdb.XRange(ctx, connStreamKey(missionID), "-", "+").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to read historical events: %w", err)
	}

	eventCh := make(chan *MissionEvent, 100)
	go func() {
		defer close(eventCh)
		var lastID string
		for _, msg := range allMsgs {
			event, err := parseXMessage(msg, missionID)
			if err != nil {
				continue
			}
			if event.Timestamp.Before(fromTimestamp) {
				lastID = msg.ID
				continue
			}
			select {
			case eventCh <- event:
			case <-ctx.Done():
				return
			}
			lastID = msg.ID
		}
		if lastID == "" {
			lastID = "$"
		}

		// Subscribe to new events.
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			msgs, err := s.rdb.XRead(ctx, &goredis.XReadArgs{
				Streams: []string{connStreamKey(missionID), lastID},
				Count:   100,
				Block:   500 * time.Millisecond,
			}).Result()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			for _, stream := range msgs {
				for _, msg := range stream.Messages {
					event, err := parseXMessage(msg, missionID)
					if err != nil {
						continue
					}
					select {
					case eventCh <- event:
					case <-ctx.Done():
						return
					}
					lastID = msg.ID
				}
			}
		}
	}()
	return eventCh, nil
}

// parseXMessage converts a Redis Stream XMessage to a MissionEvent.
func parseXMessage(msg goredis.XMessage, missionID types.ID) (*MissionEvent, error) {
	eventTypeVal, ok := msg.Values["event_type"]
	if !ok {
		return nil, fmt.Errorf("missing event_type")
	}
	eventTypeStr, ok := eventTypeVal.(string)
	if !ok {
		return nil, fmt.Errorf("event_type not a string")
	}

	createdAtVal, ok := msg.Values["created_at"]
	if !ok {
		return nil, fmt.Errorf("missing created_at")
	}
	createdAtStr, ok := createdAtVal.(string)
	if !ok {
		return nil, fmt.Errorf("created_at not a string")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	var payload any
	if payloadVal, ok := msg.Values["payload"]; ok && payloadVal != nil {
		if payloadStr, ok := payloadVal.(string); ok && payloadStr != "" {
			if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
				return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
			}
		}
	}

	return &MissionEvent{
		Type:      MissionEventType(eventTypeStr),
		MissionID: missionID,
		Timestamp: createdAt,
		Payload:   payload,
	}, nil
}

// Ensure ConnBoundEventStore implements EventStore at compile time.
var _ EventStore = (*ConnBoundEventStore)(nil)
