package checkpoint

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Span name constants for checkpoint operations following OpenTelemetry semantic conventions.
// These span names provide a hierarchical structure for checkpoint-related telemetry.
const (
	// SpanCheckpointCreate represents a checkpoint creation operation
	SpanCheckpointCreate = "gibson.checkpoint.create"

	// SpanCheckpointRestore represents a checkpoint restoration operation
	SpanCheckpointRestore = "gibson.checkpoint.restore"

	// SpanCheckpointReplay represents a time-travel replay operation
	SpanCheckpointReplay = "gibson.checkpoint.replay"

	// SpanCheckpointDelete represents a checkpoint deletion operation
	SpanCheckpointDelete = "gibson.checkpoint.delete"

	// SpanCheckpointSerialize represents a checkpoint serialization operation
	SpanCheckpointSerialize = "gibson.checkpoint.serialize"

	// SpanCheckpointDeserialize represents a checkpoint deserialization operation
	SpanCheckpointDeserialize = "gibson.checkpoint.deserialize"

	// SpanCheckpointCompress represents a checkpoint compression operation
	SpanCheckpointCompress = "gibson.checkpoint.compress"

	// SpanCheckpointEncrypt represents a checkpoint encryption operation
	SpanCheckpointEncrypt = "gibson.checkpoint.encrypt"
)

// Attribute key constants for checkpoint operations.
// These follow Gibson's attribute naming convention and OpenTelemetry semantic conventions.
const (
	// AttrThreadID is the execution thread identifier
	AttrThreadID = "gibson.checkpoint.thread_id"

	// AttrCheckpointID is the unique checkpoint identifier
	AttrCheckpointID = "gibson.checkpoint.checkpoint_id"

	// AttrMissionID is the mission identifier
	AttrMissionID = "gibson.checkpoint.mission_id"

	// AttrNodeID is the mission node identifier
	AttrNodeID = "gibson.checkpoint.node_id"

	// AttrCheckpointSizeBytes is the checkpoint size in bytes
	AttrCheckpointSizeBytes = "gibson.checkpoint.size_bytes"

	// AttrSerializationDurationMs is the serialization duration in milliseconds
	AttrSerializationDurationMs = "gibson.checkpoint.serialization_duration_ms"

	// AttrCompressionEnabled indicates if compression is enabled
	AttrCompressionEnabled = "gibson.checkpoint.compression_enabled"

	// AttrEncryptionEnabled indicates if encryption is enabled
	AttrEncryptionEnabled = "gibson.checkpoint.encryption_enabled"

	// AttrRestoreDurationMs is the restoration duration in milliseconds
	AttrRestoreDurationMs = "gibson.checkpoint.restore_duration_ms"

	// AttrNodesSkippedCount is the number of nodes skipped during restoration
	AttrNodesSkippedCount = "gibson.checkpoint.nodes_skipped_count"

	// AttrParentCheckpointID is the parent checkpoint identifier for lineage tracking
	AttrParentCheckpointID = "gibson.checkpoint.parent_checkpoint_id"

	// AttrCheckpointLabel is a human-readable checkpoint label
	AttrCheckpointLabel = "gibson.checkpoint.label"

	// AttrCheckpointVersion is the checkpoint format version
	AttrCheckpointVersion = "gibson.checkpoint.version"

	// AttrCompressionRatio is the compression ratio achieved
	AttrCompressionRatio = "gibson.checkpoint.compression_ratio"

	// AttrNodesToExecuteCount is the number of pending nodes in the checkpoint
	AttrNodesToExecuteCount = "gibson.checkpoint.nodes_to_execute_count"

	// AttrCompletedNodesCount is the number of completed nodes in the checkpoint
	AttrCompletedNodesCount = "gibson.checkpoint.completed_nodes_count"

	// AttrKeyID is the encryption key identifier
	AttrKeyID = "gibson.checkpoint.key_id"
)

// CheckpointTracer provides OpenTelemetry-based tracing for checkpoint operations.
// It creates spans for checkpoint lifecycle events including creation, restoration,
// replay, and deletion.
//
// The tracer follows a fire-and-forget pattern where tracing errors never block
// checkpoint operations. All public methods are thread-safe.
//
// Trace Hierarchy:
//   - Checkpoint Create Span (gibson.checkpoint.create)
//     ├── Serialize Span (gibson.checkpoint.serialize)
//     ├── Compress Span (gibson.checkpoint.compress) [if enabled]
//     └── Encrypt Span (gibson.checkpoint.encrypt) [if enabled]
//   - Checkpoint Restore Span (gibson.checkpoint.restore)
//   - Checkpoint Replay Span (gibson.checkpoint.replay)
type CheckpointTracer struct {
	tracer trace.Tracer
	meter  metric.Meter
}

// NewCheckpointTracer creates a new OpenTelemetry checkpoint tracer.
//
// The tracer uses the "gibson.checkpoint" instrumentation scope for both traces
// and metrics, enabling correlation between trace and metric data in observability
// platforms.
//
// Returns:
//   - *CheckpointTracer: The initialized tracer ready for use
//
// Example:
//
//	tracer := NewCheckpointTracer()
//	ctx, span := tracer.StartCheckpointCreate(ctx, threadID, missionID)
//	defer span.End()
func NewCheckpointTracer() *CheckpointTracer {
	// Get the global tracer and meter providers
	tp := otel.GetTracerProvider()
	mp := otel.GetMeterProvider()

	return &CheckpointTracer{
		tracer: tp.Tracer("gibson.checkpoint"),
		meter:  mp.Meter("gibson.checkpoint"),
	}
}

// StartCheckpointCreate starts a span for checkpoint creation.
// This should be called when beginning to create a new checkpoint.
//
// Parameters:
//   - ctx: Context for trace propagation
//   - threadID: The execution thread identifier
//   - missionID: The mission identifier
//
// Returns:
//   - context.Context: Context containing the checkpoint create span
//   - trace.Span: Span handle for adding attributes and ending
//
// Example:
//
//	ctx, span := tracer.StartCheckpointCreate(ctx, threadID, missionID)
//	defer span.End()
//	// Perform checkpoint creation...
//	AddCheckpointAttributes(span, checkpoint)
func (t *CheckpointTracer) StartCheckpointCreate(ctx context.Context, threadID, missionID string) (context.Context, trace.Span) {
	ctx, span := t.tracer.Start(ctx, SpanCheckpointCreate,
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	// Set initial attributes
	span.SetAttributes(
		attribute.String(AttrThreadID, threadID),
		attribute.String(AttrMissionID, missionID),
	)

	return ctx, span
}

// StartCheckpointRestore starts a span for checkpoint restoration.
// This should be called when beginning to restore a checkpoint.
//
// Parameters:
//   - ctx: Context for trace propagation
//   - threadID: The execution thread identifier
//   - checkpointID: The checkpoint identifier being restored
//
// Returns:
//   - context.Context: Context containing the checkpoint restore span
//   - trace.Span: Span handle for adding attributes and ending
//
// Example:
//
//	ctx, span := tracer.StartCheckpointRestore(ctx, threadID, checkpointID)
//	defer span.End()
//	// Perform restoration...
//	AddRestorationAttributes(span, result)
func (t *CheckpointTracer) StartCheckpointRestore(ctx context.Context, threadID, checkpointID string) (context.Context, trace.Span) {
	ctx, span := t.tracer.Start(ctx, SpanCheckpointRestore,
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	// Set initial attributes
	span.SetAttributes(
		attribute.String(AttrThreadID, threadID),
		attribute.String(AttrCheckpointID, checkpointID),
	)

	return ctx, span
}

// StartCheckpointReplay starts a span for time-travel replay operation.
// This creates a new execution branch from an existing checkpoint.
//
// Parameters:
//   - ctx: Context for trace propagation
//   - sourceCheckpointID: The checkpoint being replayed from
//   - newThreadID: The new thread identifier for the branched execution
//
// Returns:
//   - context.Context: Context containing the checkpoint replay span
//   - trace.Span: Span handle for adding attributes and ending
//
// Example:
//
//	ctx, span := tracer.StartCheckpointReplay(ctx, sourceCheckpointID, newThreadID)
//	defer span.End()
//	// Perform replay and branch creation...
func (t *CheckpointTracer) StartCheckpointReplay(ctx context.Context, sourceCheckpointID, newThreadID string) (context.Context, trace.Span) {
	ctx, span := t.tracer.Start(ctx, SpanCheckpointReplay,
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	// Set initial attributes
	span.SetAttributes(
		attribute.String(AttrCheckpointID, sourceCheckpointID),
		attribute.String(AttrThreadID, newThreadID),
	)

	return ctx, span
}

// AddCheckpointAttributes adds standard checkpoint attributes to a span.
// This should be called after checkpoint creation to add detailed metadata.
//
// Parameters:
//   - span: The span to add attributes to
//   - cp: The checkpoint containing metadata
//
// Example:
//
//	ctx, span := tracer.StartCheckpointCreate(ctx, threadID, missionID)
//	defer span.End()
//	checkpoint := createCheckpoint()
//	AddCheckpointAttributes(span, checkpoint)
func AddCheckpointAttributes(span trace.Span, cp *Checkpoint) {
	if span == nil || cp == nil {
		return
	}

	// Core identification attributes
	attrs := []attribute.KeyValue{
		attribute.String(AttrCheckpointID, cp.ID),
		attribute.String(AttrThreadID, cp.ThreadID),
		attribute.String(AttrMissionID, cp.MissionID.String()),
		attribute.Int(AttrCheckpointVersion, cp.Version),
	}

	// Checkpoint metadata
	if cp.ParentID != "" {
		attrs = append(attrs, attribute.String(AttrParentCheckpointID, cp.ParentID))
	}

	if cp.Label != "" {
		attrs = append(attrs, attribute.String(AttrCheckpointLabel, cp.Label))
	}

	if cp.CurrentNodeID != "" {
		attrs = append(attrs, attribute.String(AttrNodeID, cp.CurrentNodeID))
	}

	// Size and format attributes
	attrs = append(attrs,
		attribute.Int64(AttrCheckpointSizeBytes, cp.SizeBytes),
		attribute.Bool(AttrCompressionEnabled, cp.Compressed),
		attribute.Bool(AttrEncryptionEnabled, cp.Encrypted),
	)

	if cp.Encrypted && cp.KeyID != "" {
		attrs = append(attrs, attribute.String(AttrKeyID, cp.KeyID))
	}

	// State attributes
	attrs = append(attrs,
		attribute.Int(AttrCompletedNodesCount, len(cp.CompletedNodes)),
		attribute.Int(AttrNodesToExecuteCount, len(cp.PendingNodes)),
	)

	span.SetAttributes(attrs...)
}

// AddRestorationAttributes adds restoration-specific attributes to a span.
// This provides visibility into what was restored and restoration performance.
//
// Parameters:
//   - span: The span to add attributes to
//   - result: The restoration result containing metrics
//
// Example:
//
//	ctx, span := tracer.StartCheckpointRestore(ctx, threadID, checkpointID)
//	defer span.End()
//	result := restoreCheckpoint()
//	AddRestorationAttributes(span, result)
func AddRestorationAttributes(span trace.Span, result *RestorationResult) {
	if span == nil || result == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.Int64(AttrRestoreDurationMs, result.Duration.Milliseconds()),
		attribute.Int(AttrNodesSkippedCount, len(result.NodesSkipped)),
		attribute.Int(AttrNodesToExecuteCount, len(result.NodesToExecute)),
	}

	// Add checkpoint attributes if available
	if result.Checkpoint != nil {
		attrs = append(attrs,
			attribute.String(AttrCheckpointID, result.Checkpoint.ID),
			attribute.Int64(AttrCheckpointSizeBytes, result.Checkpoint.SizeBytes),
		)
	}

	span.SetAttributes(attrs...)
}

// RecordError records an error on a span with checkpoint context.
// This sets the span status to error and adds error-related attributes.
//
// Parameters:
//   - span: The span to record the error on
//   - err: The error that occurred
//   - attributes: Optional additional context attributes
//
// Example:
//
//	ctx, span := tracer.StartCheckpointCreate(ctx, threadID, missionID)
//	defer span.End()
//	if err := createCheckpoint(); err != nil {
//	    RecordError(span, err, attribute.String("checkpoint.phase", "serialization"))
//	    return err
//	}
func RecordError(span trace.Span, err error, attributes ...attribute.KeyValue) {
	if span == nil || err == nil {
		return
	}

	// Set span status to error
	span.SetStatus(codes.Error, err.Error())

	// Add error attributes
	errorAttrs := []attribute.KeyValue{
		attribute.Bool("error", true),
		attribute.String("error.message", err.Error()),
		attribute.String("error.type", "checkpoint_error"),
	}

	// Append any additional context attributes
	errorAttrs = append(errorAttrs, attributes...)

	span.SetAttributes(errorAttrs...)

	// Record error as an event for better visibility
	span.AddEvent("exception",
		trace.WithAttributes(
			attribute.String("exception.type", "checkpoint_error"),
			attribute.String("exception.message", err.Error()),
		),
	)
}

// StartSerializationSpan starts a nested span for checkpoint serialization.
// This provides detailed timing for the serialization phase of checkpoint creation.
//
// Parameters:
//   - ctx: Context containing the parent checkpoint span
//
// Returns:
//   - context.Context: Context containing the serialization span
//   - trace.Span: Span handle for adding attributes and ending
func (t *CheckpointTracer) StartSerializationSpan(ctx context.Context) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, SpanCheckpointSerialize,
		trace.WithSpanKind(trace.SpanKindInternal),
	)
}

// StartCompressionSpan starts a nested span for checkpoint compression.
// This provides detailed timing for the compression phase of checkpoint creation.
//
// Parameters:
//   - ctx: Context containing the parent checkpoint span
//
// Returns:
//   - context.Context: Context containing the compression span
//   - trace.Span: Span handle for adding attributes and ending
func (t *CheckpointTracer) StartCompressionSpan(ctx context.Context) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, SpanCheckpointCompress,
		trace.WithSpanKind(trace.SpanKindInternal),
	)
}

// StartEncryptionSpan starts a nested span for checkpoint encryption.
// This provides detailed timing for the encryption phase of checkpoint creation.
//
// Parameters:
//   - ctx: Context containing the parent checkpoint span
//
// Returns:
//   - context.Context: Context containing the encryption span
//   - trace.Span: Span handle for adding attributes and ending
func (t *CheckpointTracer) StartEncryptionSpan(ctx context.Context) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, SpanCheckpointEncrypt,
		trace.WithSpanKind(trace.SpanKindInternal),
	)
}

// StartDeserializationSpan starts a nested span for checkpoint deserialization.
// This provides detailed timing for the deserialization phase of checkpoint restoration.
//
// Parameters:
//   - ctx: Context containing the parent checkpoint span
//
// Returns:
//   - context.Context: Context containing the deserialization span
//   - trace.Span: Span handle for adding attributes and ending
func (t *CheckpointTracer) StartDeserializationSpan(ctx context.Context) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, SpanCheckpointDeserialize,
		trace.WithSpanKind(trace.SpanKindInternal),
	)
}
