// Package observability provides comprehensive observability infrastructure for the Gibson framework.
//
// This package implements distributed tracing, metrics collection, structured logging,
// health monitoring, and cost tracking for AI agent operations. It follows OpenTelemetry
// standards and GenAI semantic conventions to provide unified, vendor-neutral observability.
//
// # Architecture
//
// The observability package is organized into several key components:
//
//   - Tracing: OpenTelemetry-based distributed tracing with support for multiple exporters
//   - Metrics: Counter, gauge, and histogram metrics with OpenTelemetry integration
//   - Logging: Structured logging with automatic trace correlation
//   - Health: Component health monitoring with state change detection
//   - Cost: LLM cost tracking and budget management
//   - Middleware: Harness middleware for automatic instrumentation (see harness/middleware package)
//
// # Distributed Tracing
//
// Distributed tracing enables end-to-end visibility into agent execution flows,
// including LLM completions, tool calls, agent delegations, and finding submissions.
//
// Initialize tracing with InitTracing:
//
//	cfg := TracingConfig{
//	    Enabled:     true,
//	    Provider:    "otlp",
//	    Endpoint:    "localhost:4317",
//	    ServiceName: "gibson",
//	    SampleRate:  1.0,
//	}
//
//	tp, err := InitTracing(ctx, cfg, nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer ShutdownTracing(ctx, tp)
//
// Supported tracing providers:
//
//   - "otlp": OpenTelemetry Protocol (gRPC) - production standard
//   - "langfuse": Langfuse LLM observability platform - AI-specific features
//   - "noop": No-op provider for testing - zero overhead
//
// # GenAI Semantic Conventions
//
// The package follows OpenTelemetry GenAI semantic conventions for LLM operations:
//
//	span.SetAttributes(
//	    attribute.String("gen_ai.system", "anthropic"),
//	    attribute.String("gen_ai.request.model", "claude-3-opus"),
//	    attribute.Int("gen_ai.usage.input_tokens", 1000),
//	    attribute.Int("gen_ai.usage.output_tokens", 500),
//	)
//
// Standard GenAI span names:
//
//   - "gen_ai.chat": Synchronous chat completion
//   - "gen_ai.chat.stream": Streaming chat completion
//   - "gen_ai.tool": Tool/function call
//   - "gen_ai.embeddings": Embedding generation
//
// # Gibson-Specific Attributes
//
// Gibson-specific attributes extend GenAI conventions for security testing:
//
//	span.SetAttributes(
//	    attribute.String("gibson.mission.id", missionID),
//	    attribute.String("gibson.agent.name", "recon_agent"),
//	    attribute.Int("gibson.turn.number", 5),
//	    attribute.Float64("gibson.llm.cost", 0.015),
//	)
//
// Standard Gibson span names:
//
//   - "gibson.agent.delegate": Agent delegation
//   - "gibson.finding.submit": Security finding submission
//   - "gibson.plugin.query": Plugin method call
//   - "gibson.memory.get/set/search": Memory operations
//
// # Metrics Collection
//
// Initialize metrics with InitMetrics:
//
//	cfg := MetricsConfig{
//	    Enabled:  true,
//	    Provider: "prometheus",
//	    Port:     9090,
//	}
//
//	mp, err := InitMetrics(ctx, cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer mp.Shutdown(ctx)
//
//	meter := mp.Meter("gibson")
//	recorder := NewOpenTelemetryMetricsRecorder(meter)
//
// Record metrics:
//
//	// Counter: cumulative values that only increase
//	recorder.RecordCounter("gibson.llm.completions", 1, map[string]string{
//	    "provider": "anthropic",
//	    "model":    "claude-3-opus",
//	    "status":   "success",
//	})
//
//	// Histogram: distributions of values
//	recorder.RecordHistogram("gibson.llm.latency", 150.5, map[string]string{
//	    "provider": "anthropic",
//	    "model":    "claude-3-opus",
//	})
//
//	// Gauge: point-in-time measurements
//	recorder.RecordGauge("gibson.memory.size_bytes", 1024.0, map[string]string{
//	    "tier": "working",
//	})
//
// Convenience methods for common operations:
//
//	// Record LLM completion with all metrics
//	recorder.RecordLLMCompletion(
//	    "primary",        // slot
//	    "anthropic",      // provider
//	    "claude-3-opus",  // model
//	    "success",        // status
//	    1000,             // input tokens
//	    500,              // output tokens
//	    150.5,            // latency (ms)
//	    0.015,            // cost ($)
//	)
//
//	// Record tool call
//	recorder.RecordToolCall("nmap_scan", "success", 2500.0)
//
//	// Record finding submission
//	recorder.RecordFindingSubmitted("high", "sqli")
//
// # Structured Logging
//
// Logger provides structured logging with automatic trace correlation:
//
//	cfg := Config{Level: slog.LevelInfo, Output: os.Stdout, RedactSensitive: true}
//	logger := NewLogger(cfg).WithMission(missionID, "").WithAgent(agentName)
//
//	// Logs automatically include trace_id, span_id, mission_id, and agent_name
//	logger.Info(ctx, "Starting reconnaissance",
//	    slog.String("target", target.URL),
//	    slog.Int("port", 443),
//	)
//
// Sensitive data is automatically redacted at Info level and above:
//
//	// These fields are redacted: prompt, api_key, secret, password, token, credential
//	logger.Info(ctx, "API call",
//	    slog.String("api_key", "sk-1234"), // Logged as "[REDACTED]"
//	)
//
// Log levels:
//
//   - Debug: All fields logged, no redaction
//   - Info: Sensitive fields redacted
//   - Warn: Sensitive fields redacted
//   - Error: Sensitive fields redacted
//
// # Configuration Options
//
// TracingConfig configures distributed tracing:
//
//	type TracingConfig struct {
//	    Enabled     bool    // Enable/disable tracing
//	    Provider    string  // "otlp", "langfuse", "noop"
//	    Endpoint    string  // Exporter endpoint (e.g., "localhost:4317")
//	    ServiceName string  // Service name in traces
//	    SampleRate  float64 // Sampling rate (0.0-1.0)
//	}
//
// MetricsConfig configures metrics export:
//
//	type MetricsConfig struct {
//	    Enabled  bool   // Enable/disable metrics
//	    Provider string // "prometheus" or "otlp"
//	    Port     int    // Port for Prometheus scraping or OTLP export
//	}
//
// LoggingConfig configures structured logging:
//
//	type LoggingConfig struct {
//	    Level  string // "debug", "info", "warn", "error", "fatal"
//	    Format string // "json" or "text"
//	    Output string // "stdout", "stderr", or file path
//	}
//
// LangfuseConfig configures Langfuse LLM observability:
//
//	type LangfuseConfig struct {
//	    PublicKey string // Langfuse public key
//	    SecretKey string // Langfuse secret key
//	    Host      string // Langfuse API host
//	}
//
// # Harness Middleware
//
// Harness operations are instrumented via middleware (see harness/middleware package).
// The middleware approach provides tracing, logging, and event emission:
//
//	import "github.com/zero-day-ai/gibson/internal/harness/middleware"
//
//	// Build middleware chain
//	mw := middleware.Chain(
//	    middleware.TracingMiddleware(tracer),
//	    middleware.LoggingMiddleware(logger, middleware.LevelNormal),
//	    middleware.EventMiddleware(eventBus, errorHandler),
//	)
//
//	// Configure harness factory with middleware
//	config := harness.HarnessConfig{
//	    // ... other config
//	    Middleware: mw,
//	}
//
// The middleware automatically:
//
//   - Creates spans for all harness operations
//   - Records GenAI and Gibson attributes
//   - Tracks token usage via span attributes
//   - Emits structured logs with operation details
//   - Publishes events to the EventBus
//
// # Health Monitoring
//
// HealthMonitor tracks component health and emits metrics:
//
//	monitor := NewHealthMonitor(metricsRecorder, logger)
//
//	// Register components
//	monitor.Register("database", databaseHealthChecker)
//	monitor.Register("cache", cacheHealthChecker)
//	monitor.Register("llm_provider", llmHealthChecker)
//
//	// Check individual component
//	status, err := monitor.Check(ctx, "database")
//	if !status.IsHealthy() {
//	    log.Printf("Database unhealthy: %s", status.Message)
//	}
//
//	// Check all components
//	allHealth := monitor.CheckAll(ctx)
//
//	// Start periodic health checks
//	go monitor.StartPeriodicCheck(ctx, 30*time.Second)
//
// Components implement the HealthChecker interface:
//
//	type HealthChecker interface {
//	    Health(ctx context.Context) types.HealthStatus
//	}
//
// Health states:
//
//   - Healthy: Component operating normally
//   - Degraded: Component operational but with reduced performance
//   - Unhealthy: Component not operational
//
// The monitor emits metrics and logs state transitions:
//
//   - Degradation (healthy → degraded/unhealthy): ERROR log
//   - Recovery (degraded/unhealthy → healthy): INFO log
//   - Other transitions: WARN log
//
// # Cost Tracking
//
// CostTracker monitors LLM costs and enforces budgets:
//
//	tracker := NewCostTracker(tokenTracker, logger)
//
//	// Calculate cost for a completion
//	cost := tracker.CalculateCost(
//	    "anthropic",
//	    "claude-3-opus-20240229",
//	    1000, // input tokens
//	    500,  // output tokens
//	)
//
//	// Get mission cost
//	missionCost, err := tracker.GetMissionCost(missionID)
//
//	// Get agent cost within mission
//	agentCost, err := tracker.GetAgentCost(missionID, "recon_agent")
//
//	// Set cost threshold
//	err = tracker.SetThreshold(missionID, 10.0) // $10 USD
//
//	// Check if threshold exceeded
//	if tracker.CheckThreshold(missionID, currentCost) {
//	    log.Warn("Cost threshold exceeded!")
//	}
//
// Cost tracking integrates with OpenTelemetry:
//
//	tracker.RecordCostOnSpan(span, cost)
//
// This adds the "gibson.llm.cost" attribute to spans for cost analysis in traces.
//
// # Usage Examples
//
// Complete observability setup for production:
//
//	// 1. Initialize tracing
//	tracingCfg := TracingConfig{
//	    Enabled:     true,
//	    Provider:    "otlp",
//	    Endpoint:    "localhost:4317",
//	    ServiceName: "gibson",
//	    SampleRate:  0.1, // 10% sampling
//	}
//	tp, _ := InitTracing(ctx, tracingCfg, nil)
//	defer ShutdownTracing(ctx, tp)
//
//	// 2. Initialize metrics
//	metricsCfg := MetricsConfig{
//	    Enabled:  true,
//	    Provider: "prometheus",
//	    Port:     9090,
//	}
//	mp, _ := InitMetrics(ctx, metricsCfg)
//	defer mp.Shutdown(ctx)
//
//	// 3. Create observability primitives
//	tracer := tp.Tracer("gibson")
//	meter := mp.Meter("gibson")
//	recorder := NewOpenTelemetryMetricsRecorder(meter)
//
//	cfg := Config{Level: slog.LevelInfo, Output: os.Stdout, RedactSensitive: true}
//	logger := NewLogger(cfg).WithMission(missionID, "").WithAgent(agentName)
//
//	// 4. Create health monitor
//	monitor := NewHealthMonitor(recorder, logger)
//	monitor.Register("database", dbHealthChecker)
//	go monitor.StartPeriodicCheck(ctx, 30*time.Second)
//
//	// 5. Create cost tracker
//	costTracker := NewCostTracker(tokenTracker, logger)
//	costTracker.SetThreshold(missionID, 100.0)
//
//	// 6. Configure harness with middleware
//	mw := middleware.Chain(
//	    middleware.TracingMiddleware(tracer),
//	    middleware.LoggingMiddleware(logger, middleware.LevelNormal),
//	)
//
//	config := harness.HarnessConfig{
//	    // ... other config
//	    Middleware: mw,
//	}
//
//	// 7. Execute agent with full observability
//	h, _ := harness.NewHarnessFactory(config).Create("agent", missionCtx, targetInfo)
//	result, err := agent.Execute(ctx, task, h)
//
// # Best Practices
//
// 1. Always use context propagation for trace correlation
// 2. Set appropriate sampling rates in production (0.01-0.1)
// 3. Use WithPromptCapture(false) in production for security
// 4. Monitor health of critical components (database, LLM providers, cache)
// 5. Set cost thresholds to prevent runaway LLM usage
// 6. Use structured logging with meaningful fields
// 7. Include Gibson-specific attributes for agent operations
// 8. Aggregate metrics by mission, agent, and slot for analysis
// 9. Export traces to a backend for long-term storage and analysis
// 10. Use consistent attribute naming across the application
//
// # Performance Considerations
//
// - Use sampling in production to reduce trace volume
// - Batch spans and metrics for efficient export
// - Use no-op providers for testing to eliminate overhead
// - Avoid high-cardinality labels in metrics
// - Use async exporters to avoid blocking agent execution
// - Set reasonable flush intervals (5-10 seconds)
// - Monitor memory usage of trace buffers
//
// # Security Considerations
//
// - Disable prompt capture in production (contains sensitive data)
// - Use redaction for sensitive log fields
// - Secure exporter endpoints with TLS
// - Rotate Langfuse API keys regularly
// - Limit trace retention in storage backends
// - Sanitize URLs before logging (remove credentials)
// - Use separate exporters for PII and non-PII data
//
// # Error Handling
//
// The package defines several error types for observability failures:
//
//   - ErrExporterConnection: Failed to connect to trace/metric exporter
//   - ErrAuthenticationFailed: Invalid credentials for exporter
//   - ErrInvalidConfig: Invalid observability configuration
//   - ErrShutdownTimeout: Timeout during graceful shutdown
//
// Use error wrapping to preserve context:
//
//	if err != nil {
//	    return WrapObservabilityError(ErrExporterConnection,
//	        "failed to export traces", err)
//	}
//
// # Integration with OpenTelemetry
//
// The package is designed to work seamlessly with OpenTelemetry SDKs:
//
//   - Uses standard OpenTelemetry trace and metric APIs
//   - Follows semantic convention specifications
//   - Compatible with any OpenTelemetry backend
//   - Supports standard exporters (OTLP, Prometheus)
//   - Enables vendor-neutral observability
//
// # See Also
//
//   - OpenTelemetry GenAI Semantic Conventions: https://opentelemetry.io/docs/specs/semconv/gen-ai/
//   - OpenTelemetry Go SDK: https://github.com/open-telemetry/opentelemetry-go
//   - Langfuse Documentation: https://langfuse.com/docs
//   - Prometheus Best Practices: https://prometheus.io/docs/practices/naming/
package observability
