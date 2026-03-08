package events

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// EventBus manages event distribution to subscribers with filtering support.
//
// The EventBus is the central hub for all Gibson observability events, replacing
// both the daemon EventBus and VerboseEventBus with a unified implementation.
// It supports filtering by event type, mission ID, and agent name.
//
// Thread Safety:
//   - All methods are safe for concurrent use
//   - Multiple goroutines can publish and subscribe simultaneously
//   - Non-blocking publish prevents slow subscribers from affecting publishers
//
// Slow Consumer Handling:
//   - Subscribers receive events through buffered channels
//   - If a subscriber's buffer is full, events are dropped for that subscriber
//   - Other subscribers are not affected by slow consumers
//   - Dropped events are logged via the error handler
type EventBus interface {
	// Publish sends an event to all matching subscribers.
	// Returns an error only if the event bus is closed.
	// Never blocks on slow subscribers.
	Publish(ctx context.Context, event Event) error

	// Subscribe creates a subscription with optional filtering.
	// Returns a channel for receiving events and a cleanup function.
	// The cleanup function must be called to prevent resource leaks.
	//
	// Parameters:
	//   - ctx: Context for subscription lifetime
	//   - filter: Optional filter criteria (nil = receive all events)
	//   - bufferSize: Size of subscriber's event buffer (0 = use default)
	//
	// Returns:
	//   - <-chan Event: Channel that receives matching events
	//   - func(): Cleanup function to unsubscribe (must be called)
	Subscribe(ctx context.Context, filter Filter, bufferSize int) (<-chan Event, func())

	// Close shuts down the event bus and all subscriptions.
	// After Close returns, Publish will return an error.
	Close() error
}

// DefaultEventBus implements EventBus with buffered channels and non-blocking sends.
//
// The implementation combines best practices from both the daemon EventBus and
// VerboseEventBus:
//   - Daemon EventBus: filtering, context handling, detailed logging
//   - VerboseEventBus: simplicity, efficient non-blocking sends
//
// Architecture:
//   - RWMutex for concurrent subscriber map access
//   - Map of subscriber IDs to subscription structs
//   - Each subscription has its own buffered channel
//   - Non-blocking sends with select/default pattern
type DefaultEventBus struct {
	mu          sync.RWMutex
	subscribers map[string]*subscription
	options     *eventBusOptions
	closed      bool
}

// subscription represents a single subscriber with filtering and lifecycle management.
type subscription struct {
	id       string
	ch       chan Event
	filter   Filter
	ctx      context.Context
	cancel   context.CancelFunc
	created  time.Time
	received atomic.Int64 // Total events received (for metrics)
	dropped  atomic.Int64 // Total events dropped (for metrics)
}

// eventBusOptions holds configuration for DefaultEventBus.
type eventBusOptions struct {
	defaultBufferSize int
	errorHandler      ErrorHandler
	metricsRecorder   MetricsRecorder
}

// ErrorHandler is called when an error occurs during event bus operations.
// Common uses: logging dropped events, subscription errors, publish failures.
type ErrorHandler func(err error, context map[string]interface{})

// MetricsRecorder records metrics about event bus operations.
// Implementations can send metrics to Prometheus, StatsD, etc.
type MetricsRecorder interface {
	// RecordEventPublished is called when an event is successfully published.
	RecordEventPublished(eventType string, subscriberCount int)

	// RecordEventDropped is called when an event is dropped for a slow subscriber.
	RecordEventDropped(eventType string, subscriberID string)

	// RecordSubscriberAdded is called when a new subscriber is created.
	RecordSubscriberAdded(subscriberID string)

	// RecordSubscriberRemoved is called when a subscriber is removed.
	RecordSubscriberRemoved(subscriberID string, duration time.Duration)
}

// Option is a functional option for configuring DefaultEventBus.
type Option func(*eventBusOptions)

// WithDefaultBufferSize sets the default buffer size for subscriber channels.
// This is used when Subscribe is called with bufferSize=0.
// Default: 100 events.
func WithDefaultBufferSize(size int) Option {
	return func(opts *eventBusOptions) {
		if size > 0 {
			opts.defaultBufferSize = size
		}
	}
}

// WithErrorHandler sets the error handler for event bus operations.
// The error handler is called for dropped events, subscription errors, etc.
// Default: no-op handler.
func WithErrorHandler(handler ErrorHandler) Option {
	return func(opts *eventBusOptions) {
		if handler != nil {
			opts.errorHandler = handler
		}
	}
}

// WithMetrics sets the metrics recorder for event bus operations.
// The recorder receives metrics about publishes, drops, subscriptions, etc.
// Default: no-op recorder.
func WithMetrics(recorder MetricsRecorder) Option {
	return func(opts *eventBusOptions) {
		if recorder != nil {
			opts.metricsRecorder = recorder
		}
	}
}

// NewEventBus creates a new DefaultEventBus with the given options.
//
// Example:
//
//	bus := NewEventBus(
//		WithDefaultBufferSize(500),
//		WithErrorHandler(func(err error, ctx map[string]interface{}) {
//			log.Warn("EventBus error", "error", err, "context", ctx)
//		}),
//	)
//	defer bus.Close()
func NewEventBus(opts ...Option) *DefaultEventBus {
	options := &eventBusOptions{
		defaultBufferSize: 100,
		errorHandler:      noopErrorHandler,
		metricsRecorder:   noopMetricsRecorder{},
	}

	for _, opt := range opts {
		opt(options)
	}

	return &DefaultEventBus{
		subscribers: make(map[string]*subscription),
		options:     options,
		closed:      false,
	}
}

// Publish sends an event to all matching subscribers.
//
// The event is sent to subscribers whose filters match the event's attributes.
// If a subscriber's channel is full, the event is dropped for that subscriber
// to prevent blocking the publisher or other subscribers.
//
// Metrics and error handling:
//   - Calls MetricsRecorder.RecordEventPublished with subscriber count
//   - Calls MetricsRecorder.RecordEventDropped for each dropped event
//   - Calls ErrorHandler for dropped events with context
//
// Thread Safety: Safe for concurrent calls from multiple goroutines.
func (eb *DefaultEventBus) Publish(ctx context.Context, event Event) error {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if eb.closed {
		return fmt.Errorf("event bus is closed")
	}

	// Track metrics
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

		// Apply filter
		if !eb.matchesFilter(event, sub.filter) {
			continue
		}

		// Try to send event (non-blocking)
		select {
		case sub.ch <- event:
			sent++
			sub.received.Add(1)
		case <-ctx.Done():
			// Publisher context cancelled
			return ctx.Err()
		default:
			// Channel is full, drop event for this slow subscriber
			dropped++
			sub.dropped.Add(1)

			// Record metrics and call error handler
			eb.options.metricsRecorder.RecordEventDropped(string(event.Type), sub.id)
			eb.options.errorHandler(
				fmt.Errorf("dropped event for slow subscriber"),
				map[string]interface{}{
					"subscriber_id": sub.id,
					"event_type":    event.Type,
					"mission_id":    event.MissionID,
					"agent_name":    event.AgentName,
				},
			)
		}
	}

	// Record publish metrics
	if sent > 0 || dropped > 0 {
		eb.options.metricsRecorder.RecordEventPublished(string(event.Type), sent)
	}

	return nil
}

// Subscribe creates a new subscription with optional filtering.
//
// The returned channel will receive events matching the filter criteria.
// The cleanup function must be called to unsubscribe and prevent resource leaks.
//
// Parameters:
//   - ctx: Context for the subscription lifetime. When cancelled, the subscription
//     is marked for cleanup but the channel remains open until cleanup() is called.
//   - filter: Filter criteria for events. Pass Filter{} to receive all events.
//   - bufferSize: Size of the event buffer. Use 0 for default size (from options).
//
// Example:
//
//	events, cleanup := bus.Subscribe(ctx, Filter{
//		Types: []EventType{EventMissionStarted, EventMissionCompleted},
//		MissionID: types.NewID(),
//	}, 0)
//	defer cleanup()
//
//	for event := range events {
//		// Process event
//	}
//
// Thread Safety: Safe for concurrent calls from multiple goroutines.
func (eb *DefaultEventBus) Subscribe(ctx context.Context, filter Filter, bufferSize int) (<-chan Event, func()) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// Use default buffer size if not specified
	if bufferSize <= 0 {
		bufferSize = eb.options.defaultBufferSize
	}

	// Generate unique subscriber ID
	subscriberID := generateSubscriberID()

	// Create subscription context that inherits from parent
	subCtx, cancel := context.WithCancel(ctx)

	// Create subscription
	sub := &subscription{
		id:      subscriberID,
		ch:      make(chan Event, bufferSize),
		filter:  filter,
		ctx:     subCtx,
		cancel:  cancel,
		created: time.Now(),
	}
	sub.received.Store(0)
	sub.dropped.Store(0)

	eb.subscribers[subscriberID] = sub

	// Record metrics
	eb.options.metricsRecorder.RecordSubscriberAdded(subscriberID)

	// Cleanup function to unsubscribe
	cleanup := func() {
		eb.unsubscribe(subscriberID)
	}

	return sub.ch, cleanup
}

// unsubscribe removes a subscription and closes its channel.
// Must be called with eb.mu held by the caller.
func (eb *DefaultEventBus) unsubscribe(subscriberID string) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	sub, exists := eb.subscribers[subscriberID]
	if !exists {
		return
	}

	// Calculate subscription duration for metrics
	duration := time.Since(sub.created)

	// Cancel subscription context
	sub.cancel()

	// Close channel and remove from map
	close(sub.ch)
	delete(eb.subscribers, subscriberID)

	// Record metrics
	eb.options.metricsRecorder.RecordSubscriberRemoved(subscriberID, duration)
}

// Close shuts down the event bus and closes all subscriber channels.
//
// After Close returns:
//   - Publish will return an error
//   - All subscriber channels are closed
//   - All subscriptions are removed
//
// Close is idempotent; multiple calls are safe.
//
// Thread Safety: Safe for concurrent calls from multiple goroutines.
func (eb *DefaultEventBus) Close() error {
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

		// Record metrics
		duration := time.Since(sub.created)
		eb.options.metricsRecorder.RecordSubscriberRemoved(id, duration)

		delete(eb.subscribers, id)
	}

	return nil
}

// SubscriberCount returns the current number of active subscribers.
// Useful for monitoring and testing.
func (eb *DefaultEventBus) SubscriberCount() int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()
	return len(eb.subscribers)
}

// matchesFilter checks if an event matches a subscription filter.
// Delegates to Filter.Matches method for consistent filtering logic.
func (eb *DefaultEventBus) matchesFilter(event Event, filter Filter) bool {
	return filter.Matches(event)
}

// generateSubscriberID generates a unique subscriber ID.
// Uses timestamp + counter for uniqueness and readability.
var (
	subscriberCounter uint64
	subscriberMutex   sync.Mutex
)

func generateSubscriberID() string {
	subscriberMutex.Lock()
	defer subscriberMutex.Unlock()
	subscriberCounter++
	return fmt.Sprintf("sub-%d-%d", time.Now().UnixNano(), subscriberCounter)
}

// noopErrorHandler is the default error handler that does nothing.
func noopErrorHandler(err error, context map[string]interface{}) {}

// noopMetricsRecorder is the default metrics recorder that does nothing.
type noopMetricsRecorder struct{}

func (noopMetricsRecorder) RecordEventPublished(eventType string, subscriberCount int) {}
func (noopMetricsRecorder) RecordEventDropped(eventType string, subscriberID string)   {}
func (noopMetricsRecorder) RecordSubscriberAdded(subscriberID string)                  {}
func (noopMetricsRecorder) RecordSubscriberRemoved(subscriberID string, duration time.Duration) {
}

// Ensure DefaultEventBus implements EventBus at compile time.
var _ EventBus = (*DefaultEventBus)(nil)

// defaultBus is the global singleton EventBus instance.
var (
	defaultBus     *DefaultEventBus
	defaultBusOnce sync.Once
)

// Default returns the global singleton EventBus instance.
// The instance is created on first call with default options.
// This provides a convenient way for components to share a single event bus
// without explicit dependency injection.
//
// Example:
//
//	bus := events.Default()
//	bus.Publish(ctx, event)
//
// Thread Safety: Safe for concurrent calls from multiple goroutines.
func Default() *DefaultEventBus {
	defaultBusOnce.Do(func() {
		defaultBus = NewEventBus(
			WithDefaultBufferSize(100),
		)
	})
	return defaultBus
}
