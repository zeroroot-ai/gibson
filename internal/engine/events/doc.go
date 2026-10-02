// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package events is the typed event vocabulary the harness middleware and
// the daemon's EventBusAdapter share: Event, EventType, Filter and the
// payload structs the adapter fills from daemon events.
//
// The daemon's own EventBus (internal/server/daemon) is the live bus. It
// carries api.EventData with string event types, and the harness callback
// service publishes string-typed events onto it. This package never replaced
// it. The constants and payload types that nothing outside the package read
// were deleted (gibson#504); what remains has a reader.
//
// # Overview
//
// The EventBus provides:
//   - Thread-safe concurrent publishing and subscribing
//   - Flexible filtering by event type, mission ID, and agent name
//   - Non-blocking publish to prevent slow subscribers from affecting publishers
//   - Graceful slow-consumer handling with event dropping
//   - Configurable buffer sizes and error handling
//   - Metrics recording for monitoring
//
// # Architecture
//
// The EventBus uses a pub-sub pattern with buffered channels:
//
//	┌─────────────┐         ┌──────────────┐         ┌──────────────┐
//	│  Publisher  │────────▶│   EventBus   │────────▶│ Subscriber 1 │
//	└─────────────┘         │              │────────▶│ Subscriber 2 │
//	                        │  (filtering) │────────▶│ Subscriber 3 │
//	                        └──────────────┘         └──────────────┘
//
// Publishers call Publish() to send events to the bus.
// The bus distributes events to all matching subscribers.
// Subscribers receive events through buffered channels.
//
// # Thread Safety
//
// All EventBus methods are safe for concurrent use from multiple goroutines.
// The implementation uses:
//   - RWMutex for subscriber map access
//   - Atomic operations for subscriber counters
//   - Non-blocking channel sends to prevent deadlocks
//
// # Slow Consumer Handling
//
// If a subscriber's buffer fills up, the EventBus will:
//  1. Drop the event for that subscriber only
//  2. Call the error handler with context
//  3. Record metrics via the metrics recorder
//  4. Continue delivering to other subscribers
//
// This prevents one slow subscriber from blocking publishers or other subscribers.
//
// # Usage Example
//
//	// Create event bus with custom configuration
//	bus := events.NewEventBus(
//		events.WithDefaultBufferSize(500),
//		events.WithErrorHandler(func(err error, ctx map[string]interface{}) {
//			log.Warn("EventBus error", "error", err, "context", ctx)
//		}),
//		events.WithMetrics(myMetricsRecorder),
//	)
//	defer bus.Close()
//
//	// Subscribe to specific event types for a mission
//	events, cleanup := bus.Subscribe(ctx, events.Filter{
//		Types: []events.EventType{
//			events.EventMissionStarted,
//			events.EventMissionCompleted,
//		},
//		MissionID: missionID,
//	}, 0) // 0 = use default buffer size
//	defer cleanup()
//
//	// Process events
//	go func() {
//		for event := range events {
//			switch event.Type {
//			case events.EventMissionStarted:
//				// Handle mission started
//			case events.EventMissionCompleted:
//				// Handle mission completed
//			}
//		}
//	}()
//
//	// Publish events
//	err := bus.Publish(ctx, events.Event{
//		Type:      events.EventMissionStarted,
//		Timestamp: time.Now(),
//		MissionID: missionID,
//		Payload: events.MissionStartedPayload{
//			MissionID:    missionID,
//			MissionName: "security-scan",
//			NodeCount:    5,
//		},
//	})
//
// # Event Types
//
// EventMissionStarted and EventMissionCompleted are the named types. Every
// other event type travels as its string, the same string the daemon's
// EventBus carries in api.EventData.EventType: node.started, agent.started,
// llm.request.completed, tool.call.started, agent.finding_submitted and the
// rest. The payload structs here (MissionStartedPayload, NodeStartedPayload,
// AgentStartedPayload, ToolCallStartedPayload, ...) are what the daemon's
// EventBusAdapter and the harness middleware fill.
//
// # Filtering
//
// Subscribers can filter events using the Filter struct:
//
//	filter := events.Filter{
//		Types:     []events.EventType{events.EventMissionStarted},
//		MissionID: specificMissionID,
//		AgentName: specificAgentName,
//	}
//
// All filter fields use AND logic (event must match all specified criteria).
// Empty fields act as wildcards (match all).
//
// # Performance
//
// The EventBus is designed for high throughput:
//   - ~4M events/sec with single subscriber (278 ns/op, 0 allocs)
//   - ~400K events/sec with 10 subscribers (2.7 µs/op, 0 allocs)
//   - Non-blocking publish prevents contention
//   - Zero allocations per publish (after warmup)
package events
