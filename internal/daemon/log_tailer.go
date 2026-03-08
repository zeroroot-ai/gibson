package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/observability"
)

// SubscribeOptions configures log subscription behavior.
type SubscribeOptions struct {
	Follow       bool       // Keep streaming new entries
	TailLines    int        // Number of historical lines (0 = all)
	Since        *time.Time // Start from timestamp
	ComponentIDs []string   // List of component IDs (for multi-component subscription)
}

// Subscription represents an active log subscription.
type Subscription struct {
	ID           string
	ComponentIDs []string
	Options      SubscribeOptions
	Output       chan LogEntry
	ctx          context.Context
	cancel       context.CancelFunc
}

// LogTailer manages log watchers and subscribers for component logs.
type LogTailer struct {
	watchers    map[string]*LogWatcher          // componentID -> watcher
	subscribers map[string][]*Subscription      // componentID -> subscriptions
	buffers     map[string]*RingBuffer          // componentID -> ring buffer
	bufferSize  int
	logger      observability.Logger
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewLogTailer creates a new log tailer with the specified buffer size.
func NewLogTailer(ctx context.Context, bufferSize int, logger observability.Logger) *LogTailer {
	if bufferSize <= 0 {
		bufferSize = 10000 // Default buffer size
	}

	tailerCtx, cancel := context.WithCancel(ctx)

	return &LogTailer{
		watchers:    make(map[string]*LogWatcher),
		subscribers: make(map[string][]*Subscription),
		buffers:     make(map[string]*RingBuffer),
		bufferSize:  bufferSize,
		logger:      logger,
		ctx:         tailerCtx,
		cancel:      cancel,
	}
}

// StartWatching begins watching a component's log file.
func (t *LogTailer) StartWatching(componentID string, logPath string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if already watching
	if _, exists := t.watchers[componentID]; exists {
		t.logger.Debug(t.ctx, "already watching component", "component_id", componentID)
		return nil
	}

	// Create log watcher
	watcher, err := NewLogWatcher(t.ctx, logPath, t.logger)
	if err != nil {
		return fmt.Errorf("failed to create log watcher: %w", err)
	}

	// Start watching
	if err := watcher.Start(); err != nil {
		return fmt.Errorf("failed to start log watcher: %w", err)
	}

	// Create buffer
	buffer := NewRingBuffer(t.bufferSize)

	// Store watcher and buffer
	t.watchers[componentID] = watcher
	t.buffers[componentID] = buffer

	// Start processing lines from watcher
	t.wg.Add(1)
	go t.processLines(componentID, watcher, buffer)

	t.logger.Info(t.ctx, "started watching component logs", "component_id", componentID, "log_path", logPath)

	return nil
}

// StopWatching stops watching a component's log file.
func (t *LogTailer) StopWatching(componentID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	watcher, exists := t.watchers[componentID]
	if !exists {
		return fmt.Errorf("component not being watched: %s", componentID)
	}

	// Stop watcher
	if err := watcher.Close(); err != nil {
		t.logger.Error(t.ctx, "error closing log watcher", "error", err, "component_id", componentID)
	}

	// Remove watcher and buffer
	delete(t.watchers, componentID)
	delete(t.buffers, componentID)

	// Cancel all subscriptions for this component
	if subs, exists := t.subscribers[componentID]; exists {
		for _, sub := range subs {
			sub.cancel()
		}
		delete(t.subscribers, componentID)
	}

	t.logger.Info(t.ctx, "stopped watching component logs", "component_id", componentID)

	return nil
}

// Subscribe creates a subscription for receiving log entries.
// For multi-component subscriptions, provide multiple component IDs in options.ComponentIDs.
func (t *LogTailer) Subscribe(ctx context.Context, opts SubscribeOptions) (*Subscription, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If no component IDs specified, this is an error
	if len(opts.ComponentIDs) == 0 {
		return nil, fmt.Errorf("at least one component ID must be specified")
	}

	// Verify all components are being watched
	for _, componentID := range opts.ComponentIDs {
		if _, exists := t.watchers[componentID]; !exists {
			return nil, fmt.Errorf("component not being watched: %s", componentID)
		}
	}

	// Create subscription
	subCtx, cancel := context.WithCancel(ctx)
	sub := &Subscription{
		ID:           fmt.Sprintf("sub-%d", time.Now().UnixNano()),
		ComponentIDs: opts.ComponentIDs,
		Options:      opts,
		Output:       make(chan LogEntry, 100),
		ctx:          subCtx,
		cancel:       cancel,
	}

	// Add to subscribers for each component
	for _, componentID := range opts.ComponentIDs {
		t.subscribers[componentID] = append(t.subscribers[componentID], sub)
	}

	// Start subscription handler
	t.wg.Add(1)
	go t.handleSubscription(sub)

	t.logger.Debug(t.ctx, "created log subscription",
		"subscription_id", sub.ID,
		"component_ids", opts.ComponentIDs,
		"follow", opts.Follow,
		"tail_lines", opts.TailLines)

	return sub, nil
}

// Unsubscribe removes a subscription.
func (t *LogTailer) Unsubscribe(sub *Subscription) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Cancel subscription context
	sub.cancel()

	// Remove from subscribers map
	for _, componentID := range sub.ComponentIDs {
		if subs, exists := t.subscribers[componentID]; exists {
			filtered := make([]*Subscription, 0, len(subs))
			for _, s := range subs {
				if s.ID != sub.ID {
					filtered = append(filtered, s)
				}
			}
			if len(filtered) > 0 {
				t.subscribers[componentID] = filtered
			} else {
				delete(t.subscribers, componentID)
			}
		}
	}

	t.logger.Debug(t.ctx, "removed log subscription", "subscription_id", sub.ID)
}

// GetHistory returns recent log entries from buffer.
func (t *LogTailer) GetHistory(componentID string, lines int) ([]LogEntry, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	buffer, exists := t.buffers[componentID]
	if !exists {
		return nil, fmt.Errorf("component not being watched: %s", componentID)
	}

	return buffer.GetLast(lines), nil
}

// Close stops all watchers and closes all subscriptions.
func (t *LogTailer) Close() error {
	t.cancel()
	t.wg.Wait()

	t.mu.Lock()
	defer t.mu.Unlock()

	// Close all watchers
	for componentID, watcher := range t.watchers {
		if err := watcher.Close(); err != nil {
			t.logger.Error(t.ctx, "error closing log watcher", "error", err, "component_id", componentID)
		}
	}

	// Cancel all subscriptions
	for _, subs := range t.subscribers {
		for _, sub := range subs {
			sub.cancel()
			close(sub.Output)
		}
	}

	t.logger.Info(t.ctx, "log tailer closed")

	return nil
}

// processLines reads lines from a watcher and adds them to the buffer and subscriptions.
func (t *LogTailer) processLines(componentID string, watcher *LogWatcher, buffer *RingBuffer) {
	defer t.wg.Done()

	for {
		select {
		case <-t.ctx.Done():
			return

		case line, ok := <-watcher.Lines():
			if !ok {
				return
			}

			// Parse line into log entry
			entry := t.parseLine(line, componentID)

			// Add to buffer
			buffer.Add(entry)

			// Fan out to subscribers
			t.mu.RLock()
			subs := t.subscribers[componentID]
			for _, sub := range subs {
				// Only send if following or if within history window
				if sub.Options.Follow {
					select {
					case sub.Output <- entry:
					default:
						// Subscriber is slow, drop entry
						t.logger.Warn(t.ctx, "subscriber channel full, dropping log entry",
							"subscription_id", sub.ID,
							"component_id", componentID)
					}
				}
			}
			t.mu.RUnlock()
		}
	}
}

// handleSubscription manages a subscription lifecycle.
func (t *LogTailer) handleSubscription(sub *Subscription) {
	defer t.wg.Done()
	defer close(sub.Output)

	// Send historical entries first
	if sub.Options.TailLines > 0 || sub.Options.Since != nil {
		t.sendHistoricalEntries(sub)
	}

	// If not following, we're done
	if !sub.Options.Follow {
		return
	}

	// Wait for subscription to be cancelled
	<-sub.ctx.Done()
}

// sendHistoricalEntries sends historical log entries to a subscription.
func (t *LogTailer) sendHistoricalEntries(sub *Subscription) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// For multi-component subscriptions, we need to merge entries by timestamp
	var allEntries []LogEntry

	for _, componentID := range sub.ComponentIDs {
		buffer, exists := t.buffers[componentID]
		if !exists {
			continue
		}

		var entries []LogEntry
		if sub.Options.Since != nil {
			entries = buffer.GetSince(*sub.Options.Since)
		} else {
			entries = buffer.GetLast(sub.Options.TailLines)
		}

		allEntries = append(allEntries, entries...)
	}

	// Sort entries by timestamp for multi-component view
	if len(sub.ComponentIDs) > 1 {
		sort.Slice(allEntries, func(i, j int) bool {
			return allEntries[i].Timestamp.Before(allEntries[j].Timestamp)
		})
	}

	// Send historical entries
	for _, entry := range allEntries {
		select {
		case sub.Output <- entry:
		case <-sub.ctx.Done():
			return
		}
	}
}

// parseLine parses a log line into a LogEntry.
// Attempts to parse as JSON first, falls back to plain text.
func (t *LogTailer) parseLine(line string, componentID string) LogEntry {
	entry := LogEntry{
		Timestamp: time.Now(),
		Component: componentID,
		Message:   line,
	}

	// Try to parse as JSON structured log
	var structured map[string]any
	if err := json.Unmarshal([]byte(line), &structured); err == nil {
		// Extract common fields
		if ts, ok := structured["timestamp"].(string); ok {
			if parsedTime, err := time.Parse(time.RFC3339, ts); err == nil {
				entry.Timestamp = parsedTime
			}
		} else if ts, ok := structured["time"].(string); ok {
			if parsedTime, err := time.Parse(time.RFC3339, ts); err == nil {
				entry.Timestamp = parsedTime
			}
		}

		if level, ok := structured["level"].(string); ok {
			entry.Level = level
		}

		if msg, ok := structured["message"].(string); ok {
			entry.Message = msg
		} else if msg, ok := structured["msg"].(string); ok {
			entry.Message = msg
		}

		// Store remaining fields
		entry.Fields = make(map[string]any)
		for k, v := range structured {
			if k != "timestamp" && k != "time" && k != "level" && k != "message" && k != "msg" && k != "component" {
				entry.Fields[k] = v
			}
		}
	}

	return entry
}

// IsWatching returns true if the component is being watched.
func (t *LogTailer) IsWatching(componentID string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	_, exists := t.watchers[componentID]
	return exists
}

// GetWatchedComponents returns a list of all components being watched.
func (t *LogTailer) GetWatchedComponents() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	components := make([]string, 0, len(t.watchers))
	for componentID := range t.watchers {
		components = append(components, componentID)
	}

	return components
}
