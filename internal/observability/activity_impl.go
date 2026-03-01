package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
	"go.opentelemetry.io/otel/trace"
)

// DefaultActivityLogger implements ActivityLogger with JSON output.
type DefaultActivityLogger struct {
	mu              sync.RWMutex
	level           ActivityLevel
	maxContentLen   int
	output          json.Encoder
	missionID       string
	agentName       string
	langfuseTraceID string

	// Buffer for async writes
	eventChan chan ActivityEvent
	doneChan  chan struct{}
	wg        sync.WaitGroup

	// Metrics (atomic counters for internal tracking)
	eventsEmitted atomic.Int64
	eventsDropped atomic.Int64

	// Prometheus metrics
	metrics *ActivityMetrics
}

// NewActivityLogger creates a new activity logger with the given configuration.
func NewActivityLogger(cfg ActivityLoggerConfig) (*DefaultActivityLogger, error) {
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 10000
	}
	if cfg.MaxContentLength <= 0 {
		cfg.MaxContentLength = 500
	}

	logger := &DefaultActivityLogger{
		level:           cfg.Level,
		maxContentLen:   cfg.MaxContentLength,
		output:          *json.NewEncoder(cfg.Output),
		missionID:       cfg.MissionID,
		agentName:       cfg.AgentName,
		langfuseTraceID: cfg.LangfuseTraceID,
		eventChan:       make(chan ActivityEvent, cfg.BufferSize),
		doneChan:        make(chan struct{}),
		metrics:         cfg.Metrics,
	}

	// Start async writer goroutine
	logger.wg.Add(1)
	go logger.writeLoop()

	return logger, nil
}

// writeLoop processes events from the buffer asynchronously.
func (l *DefaultActivityLogger) writeLoop() {
	defer l.wg.Done()

	for {
		select {
		case event := <-l.eventChan:
			if err := l.output.Encode(event); err != nil {
				// Log encoding error to stderr, don't block
				fmt.Fprintf(os.Stderr, "activity logger encode error: %v\n", err)
			} else {
				// Increment atomic counter
				l.eventsEmitted.Add(1)

				// Record Prometheus metric with labels
				if l.metrics != nil {
					l.metrics.RecordEventEmitted(
						event.EventType.String(),
						event.AgentName,
						event.Level,
					)
				}

				// Update buffer size gauge (approximate - len is safe for channels)
				if l.metrics != nil {
					l.metrics.RecordBufferSize(len(l.eventChan))
				}
			}

		case <-l.doneChan:
			// Drain remaining events with timeout
			timeout := time.After(5 * time.Second)
		drainLoop:
			for {
				select {
				case event := <-l.eventChan:
					if err := l.output.Encode(event); err == nil {
						l.eventsEmitted.Add(1)
						if l.metrics != nil {
							l.metrics.RecordEventEmitted(
								event.EventType.String(),
								event.AgentName,
								event.Level,
							)
						}
					}
				case <-timeout:
					break drainLoop
				default:
					break drainLoop
				}
			}
			return
		}
	}
}

// Emit sends an event to the buffer for async writing.
func (l *DefaultActivityLogger) Emit(ctx context.Context, event ActivityEvent) {
	// Check if event should be logged at current level
	if !l.shouldLog(event.EventType) {
		return
	}

	// Enrich event with context
	event = l.enrichEvent(ctx, event)

	// Non-blocking send to buffer
	select {
	case l.eventChan <- event:
		// Event queued successfully
		// Update buffer size gauge after queuing
		if l.metrics != nil {
			l.metrics.RecordBufferSize(len(l.eventChan))
		}
	default:
		// Buffer full, drop event and record metrics
		l.eventsDropped.Add(1)
		if l.metrics != nil {
			l.metrics.RecordEventDropped()
		}
	}
}

// enrichEvent adds context fields from context and logger state.
func (l *DefaultActivityLogger) enrichEvent(ctx context.Context, event ActivityEvent) ActivityEvent {
	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Set level based on event type
	if event.Level == "" {
		event.Level = l.getLevelForEvent(event.EventType)
	}

	// Extract OpenTelemetry trace context
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		spanCtx := span.SpanContext()
		event.TraceID = spanCtx.TraceID().String()
		event.SpanID = spanCtx.SpanID().String()
	}

	// Add mission and agent context from logger
	if event.MissionID == "" && l.missionID != "" {
		event.MissionID = l.missionID
	}
	if event.AgentName == "" && l.agentName != "" {
		event.AgentName = l.agentName
	}

	// Add Langfuse trace ID if available
	if l.langfuseTraceID != "" {
		event.LangfuseTraceID = l.langfuseTraceID
	}

	return event
}

// getLevelForEvent returns the log level string for an event type
func (l *DefaultActivityLogger) getLevelForEvent(eventType ActivityEventType) string {
	switch eventType {
	case EventError:
		return "ERROR"
	case EventFinding:
		return "WARN"
	default:
		return "INFO"
	}
}

// shouldLog determines if an event should be logged at the current level.
func (l *DefaultActivityLogger) shouldLog(eventType ActivityEventType) bool {
	l.mu.RLock()
	level := l.level
	l.mu.RUnlock()

	switch level {
	case ActivityLevelQuiet:
		return eventType == EventError || eventType == EventFinding
	case ActivityLevelNormal:
		return eventType == EventAgentStart || eventType == EventAgentEnd ||
			eventType == EventFinding || eventType == EventError ||
			eventType == EventDecision
	case ActivityLevelVerbose, ActivityLevelDebug:
		return true
	default:
		return false
	}
}

// truncateContent shortens content if it exceeds maxContentLen.
func (l *DefaultActivityLogger) truncateContent(content string) (string, bool) {
	l.mu.RLock()
	maxLen := l.maxContentLen
	level := l.level
	l.mu.RUnlock()

	// No truncation in debug mode
	if level == ActivityLevelDebug || len(content) <= maxLen {
		return content, false
	}

	// Keep beginning and end with ellipsis in middle
	if maxLen < 10 {
		return content[:maxLen], true
	}

	halfLen := (maxLen - 5) / 2 // 5 chars for " ... "
	if halfLen <= 0 || halfLen*2 > len(content) {
		return content[:maxLen], true
	}

	return content[:halfLen] + " ... " + content[len(content)-halfLen:], true
}

// Level returns the current activity logging level.
func (l *DefaultActivityLogger) Level() ActivityLevel {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.level
}

// SetLevel changes the activity logging level.
func (l *DefaultActivityLogger) SetLevel(level ActivityLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Flush ensures all buffered events are written.
func (l *DefaultActivityLogger) Flush() error {
	// Send signal to drain
	close(l.doneChan)
	// Wait for write loop to finish
	l.wg.Wait()
	return nil
}

// Close shuts down the logger gracefully.
func (l *DefaultActivityLogger) Close() error {
	// Close is idempotent - check if already closed
	select {
	case <-l.doneChan:
		// Already closed
		return nil
	default:
		return l.Flush()
	}
}

// EmitAgentStart logs an agent starting execution.
func (l *DefaultActivityLogger) EmitAgentStart(ctx context.Context, agentName string, taskDescription string) {
	payload := AgentStartPayload{
		TaskDescription: taskDescription,
	}

	event := ActivityEvent{
		EventType: EventAgentStart,
		AgentName: agentName,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitAgentEnd logs an agent completing execution.
func (l *DefaultActivityLogger) EmitAgentEnd(ctx context.Context, agentName string, status string, durationMs int64) {
	payload := AgentEndPayload{
		Status:     status,
		DurationMs: durationMs,
	}

	event := ActivityEvent{
		EventType: EventAgentEnd,
		AgentName: agentName,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitLLMPrompt logs messages sent to an LLM.
// Emits one event per message with index for correlation.
func (l *DefaultActivityLogger) EmitLLMPrompt(ctx context.Context, slot string, messages []llm.Message) {
	messageCount := len(messages)

	for idx, msg := range messages {
		content, truncated := l.truncateContent(msg.Content)

		payload := LLMPromptPayload{
			Slot:             slot,
			Role:             msg.Role.String(),
			Content:          content,
			ContentTruncated: truncated,
			ContentLength:    len(msg.Content),
			MessageIndex:     idx,
			MessageCount:     messageCount,
		}

		event := ActivityEvent{
			EventType: EventLLMPrompt,
			Payload:   l.structToMap(payload),
		}

		l.Emit(ctx, event)
	}
}

// EmitLLMResponse logs an LLM response.
func (l *DefaultActivityLogger) EmitLLMResponse(ctx context.Context, slot string, response *llm.CompletionResponse) {
	if response == nil {
		return
	}

	content, truncated := l.truncateContent(response.Message.Content)

	// Extract tool call names if present
	var toolCalls []string
	for _, tc := range response.Message.ToolCalls {
		toolCalls = append(toolCalls, tc.Name)
	}

	payload := LLMResponsePayload{
		Slot:             slot,
		Model:            response.Model,
		Content:          content,
		ContentTruncated: truncated,
		ContentLength:    len(response.Message.Content),
		InputTokens:      response.Usage.PromptTokens,
		OutputTokens:     response.Usage.CompletionTokens,
		FinishReason:     response.FinishReason.String(),
		ToolCalls:        toolCalls,
	}

	event := ActivityEvent{
		EventType: EventLLMResponse,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitToolCall logs a tool invocation.
func (l *DefaultActivityLogger) EmitToolCall(ctx context.Context, toolName string, params interface{}) {
	payload := ToolCallPayload{
		ToolName:   toolName,
		Parameters: params,
		Remote:     false, // Default to false, can be enhanced later
	}

	event := ActivityEvent{
		EventType: EventToolCall,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitToolResult logs a tool execution result.
func (l *DefaultActivityLogger) EmitToolResult(ctx context.Context, toolName string, result interface{}, durationMs int64, err error) {
	payload := ToolResultPayload{
		ToolName:  toolName,
		Success:   err == nil,
		LatencyMs: durationMs,
	}

	if err != nil {
		payload.Error = err.Error()
	} else {
		payload.Result = result
		// Estimate result size
		if result != nil {
			if data, jsonErr := json.Marshal(result); jsonErr == nil {
				payload.ResultSize = len(data)
			}
		}
	}

	event := ActivityEvent{
		EventType: EventToolResult,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitFinding logs a security finding discovery.
func (l *DefaultActivityLogger) EmitFinding(ctx context.Context, finding *agent.Finding) {
	if finding == nil {
		return
	}

	payload := FindingPayload{
		FindingID:  finding.ID.String(),
		Title:      finding.Title,
		Severity:   string(finding.Severity),
		Confidence: finding.Confidence,
		Category:   finding.Category,
		CWE:        finding.CWE,
	}

	event := ActivityEvent{
		EventType: EventFinding,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitDecision logs an orchestrator decision.
func (l *DefaultActivityLogger) EmitDecision(ctx context.Context, action string, target string, reasoning string, confidence float64) {
	payload := DecisionPayload{
		Action:     action,
		Target:     target,
		Reasoning:  reasoning,
		Confidence: confidence,
	}

	event := ActivityEvent{
		EventType: EventDecision,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitError logs an error event.
func (l *DefaultActivityLogger) EmitError(ctx context.Context, operation string, err error) {
	if err == nil {
		return
	}

	payload := ErrorPayload{
		Operation: operation,
		Error:     err.Error(),
	}

	event := ActivityEvent{
		EventType: EventError,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitMemoryStore logs a memory storage operation.
func (l *DefaultActivityLogger) EmitMemoryStore(ctx context.Context, tier string, key string, dataSize int) {
	payload := MemoryStorePayload{
		Tier:     tier,
		Key:      key,
		DataSize: dataSize,
	}

	event := ActivityEvent{
		EventType: EventMemoryStore,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitMemoryRecall logs a memory recall operation.
func (l *DefaultActivityLogger) EmitMemoryRecall(ctx context.Context, tier string, key string, found bool) {
	payload := MemoryRecallPayload{
		Tier:  tier,
		Key:   key,
		Found: found,
	}

	event := ActivityEvent{
		EventType: EventMemoryRecall,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitGraphRAGStore logs a GraphRAG entity storage operation.
func (l *DefaultActivityLogger) EmitGraphRAGStore(ctx context.Context, entityType string, count int) {
	payload := GraphRAGStorePayload{
		EntityType: entityType,
		Count:      count,
	}

	event := ActivityEvent{
		EventType: EventGraphRAGStore,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// EmitDelegation logs an agent delegation operation.
func (l *DefaultActivityLogger) EmitDelegation(ctx context.Context, parentAgent string, childAgent string, taskDescription string) {
	payload := DelegationPayload{
		ParentAgent:     parentAgent,
		ChildAgent:      childAgent,
		TaskDescription: taskDescription,
	}

	event := ActivityEvent{
		EventType: EventDelegation,
		Payload:   l.structToMap(payload),
	}

	l.Emit(ctx, event)
}

// structToMap converts a struct to map[string]interface{} using JSON marshaling
func (l *DefaultActivityLogger) structToMap(v interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Use JSON marshal/unmarshal for reliable conversion
	data, err := json.Marshal(v)
	if err != nil {
		return result
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return result
	}

	return result
}
