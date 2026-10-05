// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package observability holds the daemon's logging, metrics and tracing
// setup. It follows OpenTelemetry and the GenAI semantic conventions.
//
// # Setup
//
// InitOTelObservability builds the tracer and meter providers from an
// OTelConfig and returns an OTelObservabilityStack. Close shuts the stack
// down (otel_factory.go). Config, TracingConfig, MetricsConfig, LoggingConfig
// and OTLPConfig are the configuration types, and ConfigFromEnv reads them
// from the environment (config.go).
//
// # Logging
//
// Logger wraps slog. NewLogger and NewLoggerFromSlog build one. WithMission,
// WithAgent, WithNode and WithComponent return a Logger that adds the named
// attribute to each record (logging.go). ContentLoggingConfig decides how much
// prompt and tool content a record carries, and Redact and Truncate apply it
// (config.go, redaction.go).
//
// # Metrics
//
// OTelMetricsRecorder records the daemon's metrics through an OpenTelemetry
// meter, and NoopMetricsRecorder records nothing (otel_metrics.go).
// MetricsServer serves the Prometheus endpoint (metrics_server.go).
//
// # Tracing
//
// tracing.go, genai.go and attributes.go hold the span options and the
// attribute names. The gen_ai.* names follow the GenAI semantic conventions.
// The gibson.* names are specific to this platform.
//
// # Events and errors
//
// event_types.go defines the payload types of the mission, LLM, tool and
// finding events. errors.go defines ObservabilityError and the ErrorHandler
// that decides what a failed export does.
//
// # Health
//
// health.go defines HealthMonitor and the HealthChecker interface.
package observability
