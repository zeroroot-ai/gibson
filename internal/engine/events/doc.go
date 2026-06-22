// Package events provides a unified event bus for Gibson observability.
//
// The events package replaces both the daemon EventBus and VerboseEventBus
// with a single, unified implementation that serves as the central hub for
// all observability events in the Gibson system.
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
// Events are organized into categories:
//   - Mission Lifecycle: mission.started, mission.completed, mission.failed
//   - Node Execution: node.started, node.completed, node.failed
//   - Agent Lifecycle: agent.registered, agent.started, agent.completed
//   - LLM Requests: llm.request.started, llm.stream.chunk, etc.
//   - Tool Calls: tool.call.started, tool.call.completed
//   - Findings: finding.discovered, agent.finding_submitted
//   - Memory: memory.get, memory.set, memory.search
//   - System: system.daemon_started, system.component_registered
//
// Each event type has a corresponding payload type (e.g., MissionStartedPayload)
// that defines the structured data for that event.
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
//
// # Migration Guide
//
// Migrating from daemon.EventBus:
//   - Replace api.EventData with events.Event
//   - Use events.EventType constants instead of string literals
//   - Update Subscribe signature (now includes Filter and bufferSize)
//   - Use typed payloads instead of embedded structs
//
// Migrating from verbose.VerboseEventBus:
//   - Replace VerboseEvent with events.Event
//   - Use events.EventType constants for verbose events
//   - Add filtering if needed (previously not supported)
//   - Update Emit() calls to Publish()
package events
