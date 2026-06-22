package component

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Component attribute keys for observability.
// Following Gibson's "gibson.component.*" convention for consistency.
const (
	// AttrComponentKind is the type of component (agent, tool, plugin)
	AttrComponentKind = "gibson.component.kind"

	// AttrComponentName is the name of the component
	AttrComponentName = "gibson.component.name"

	// AttrComponentVersion is the version of the component
	AttrComponentVersion = "gibson.component.version"

	// AttrComponentSource is where the component originates from
	AttrComponentSource = "gibson.component.source"

	// AttrComponentStatus is the current runtime status of the component
	AttrComponentStatus = "gibson.component.status"

	// AttrComponentPort is the network port for the component
	AttrComponentPort = "gibson.component.port"

	// AttrComponentPID is the process ID for running components
	AttrComponentPID = "gibson.component.pid"

	// AttrRepoURL is the repository URL for external components
	AttrRepoURL = "gibson.component.repo_url"

	// AttrBuildCommand is the build command used
	AttrBuildCommand = "gibson.component.build_command"

	// AttrBuildDuration is the build duration in milliseconds
	AttrBuildDuration = "gibson.component.build_duration_ms"
)

// Span name constants for component operations.
// Following Gibson's "gibson.component.*" convention.
const (
	// SpanComponentInstall represents a component installation operation
	SpanComponentInstall = "gibson.component.install"

	// SpanComponentBuild represents a component build operation
	SpanComponentBuild = "gibson.component.build"

	// SpanComponentStart represents a component start operation
	SpanComponentStart = "gibson.component.start"

	// SpanComponentStop represents a component stop operation
	SpanComponentStop = "gibson.component.stop"

	// SpanComponentHealth represents a health check operation
	SpanComponentHealth = "gibson.component.health"

	// SpanComponentUninstall represents a component uninstall operation
	SpanComponentUninstall = "gibson.component.uninstall"

	// SpanComponentUpdate represents a component update operation
	SpanComponentUpdate = "gibson.component.update"
)

// ComponentAttributes creates OpenTelemetry attributes from a Component.
// Includes component metadata, runtime status, and resource information.
func ComponentAttributes(component *Component) []attribute.KeyValue {
	if component == nil {
		return []attribute.KeyValue{}
	}

	attrs := make([]attribute.KeyValue, 0, 10)

	// Core component attributes
	attrs = append(attrs,
		attribute.String(AttrComponentKind, component.Kind.String()),
		attribute.String(AttrComponentName, component.Name),
		attribute.String(AttrComponentVersion, component.Version),
		attribute.String(AttrComponentSource, component.Source.String()),
		attribute.String(AttrComponentStatus, component.Status.String()),
	)

	// Add paths if present
	if component.RepoPath != "" {
		attrs = append(attrs, attribute.String("gibson.component.repo_path", component.RepoPath))
	}
	if component.BinPath != "" {
		attrs = append(attrs, attribute.String("gibson.component.bin_path", component.BinPath))
	}

	// Add port if set (for running components)
	if component.Port > 0 {
		attrs = append(attrs, attribute.Int(AttrComponentPort, component.Port))
	}

	// Add PID if set (for running components)
	if component.PID > 0 {
		attrs = append(attrs, attribute.Int(AttrComponentPID, component.PID))
	}

	// Add timestamps
	if !component.CreatedAt.IsZero() {
		attrs = append(attrs, attribute.String("gibson.component.created_at", component.CreatedAt.Format("2006-01-02T15:04:05Z07:00")))
	}

	if !component.UpdatedAt.IsZero() {
		attrs = append(attrs, attribute.String("gibson.component.updated_at", component.UpdatedAt.Format("2006-01-02T15:04:05Z07:00")))
	}

	if component.StartedAt != nil {
		attrs = append(attrs, attribute.String("gibson.component.started_at", component.StartedAt.Format("2006-01-02T15:04:05Z07:00")))
	}

	if component.StoppedAt != nil {
		attrs = append(attrs, attribute.String("gibson.component.stopped_at", component.StoppedAt.Format("2006-01-02T15:04:05Z07:00")))
	}

	// Add manifest metadata if available
	if component.Manifest != nil {
		attrs = append(attrs, ManifestAttributes(component.Manifest)...)
	}

	return attrs
}

// AddComponentAttributes adds component attributes to an existing span.
// This is a convenience function for adding attributes to spans created elsewhere.
func AddComponentAttributes(span trace.Span, component *Component) {
	if span == nil || component == nil {
		return
	}

	span.SetAttributes(ComponentAttributes(component)...)
}

// ManifestAttributes creates OpenTelemetry attributes from a component Manifest.
// Includes manifest metadata and configuration details.
func ManifestAttributes(manifest *Manifest) []attribute.KeyValue {
	if manifest == nil {
		return []attribute.KeyValue{}
	}

	attrs := make([]attribute.KeyValue, 0, 5)

	// Add manifest metadata
	if manifest.Description != "" {
		attrs = append(attrs, attribute.String("gibson.component.description", manifest.Description))
	}

	if manifest.Author != "" {
		attrs = append(attrs, attribute.String("gibson.component.author", manifest.Author))
	}

	if manifest.License != "" {
		attrs = append(attrs, attribute.String("gibson.component.license", manifest.License))
	}

	// Add runtime configuration
	if manifest.Runtime != nil {
		if manifest.Runtime.Entrypoint != "" {
			attrs = append(attrs, attribute.String("gibson.component.entrypoint", manifest.Runtime.Entrypoint))
		}

		if manifest.Runtime.HealthURL != "" {
			attrs = append(attrs, attribute.String("gibson.component.health_url", manifest.Runtime.HealthURL))
		}
	}

	// Add build configuration
	if manifest.Build != nil && manifest.Build.Command != "" {
		attrs = append(attrs, attribute.String(AttrBuildCommand, manifest.Build.Command))
	}

	// Add capabilities count
	// TODO: Uncomment when Capabilities field is added to Manifest
	// if len(manifest.Capabilities) > 0 {
	// 	attrs = append(attrs, attribute.Int("gibson.component.capabilities_count", len(manifest.Capabilities)))
	// }

	return attrs
}

// InstallResultAttributes creates OpenTelemetry attributes from an InstallResult.
// Includes installation metrics and outcomes.
func InstallResultAttributes(result *InstallResult) []attribute.KeyValue {
	if result == nil {
		return []attribute.KeyValue{}
	}

	attrs := make([]attribute.KeyValue, 0, 5)

	attrs = append(attrs,
		attribute.Bool("gibson.component.installed", result.Installed),
		attribute.Bool("gibson.component.updated", result.Updated),
		attribute.Float64("gibson.component.install_duration_ms", float64(result.Duration.Milliseconds())),
	)

	if result.Path != "" {
		attrs = append(attrs, attribute.String("gibson.component.install_path", result.Path))
	}

	if result.BuildOutput != "" {
		// Don't include full build output, just indicate it's present
		attrs = append(attrs, attribute.Bool("gibson.component.has_build_output", true))
		attrs = append(attrs, attribute.Int("gibson.component.build_output_length", len(result.BuildOutput)))
	}

	return attrs
}

// UpdateResultAttributes creates OpenTelemetry attributes from an UpdateResult.
// Includes update metrics and version changes.
func UpdateResultAttributes(result *UpdateResult) []attribute.KeyValue {
	if result == nil {
		return []attribute.KeyValue{}
	}

	attrs := make([]attribute.KeyValue, 0, 6)

	attrs = append(attrs,
		attribute.Bool("gibson.component.updated", result.Updated),
		attribute.Bool("gibson.component.restarted", result.Restarted),
		attribute.Float64("gibson.component.update_duration_ms", float64(result.Duration.Milliseconds())),
	)

	if result.OldVersion != "" {
		attrs = append(attrs, attribute.String("gibson.component.old_version", result.OldVersion))
	}

	if result.NewVersion != "" {
		attrs = append(attrs, attribute.String("gibson.component.new_version", result.NewVersion))
	}

	if result.Path != "" {
		attrs = append(attrs, attribute.String("gibson.component.path", result.Path))
	}

	if result.BuildOutput != "" {
		// Don't include full build output, just indicate it's present
		attrs = append(attrs, attribute.Bool("gibson.component.has_build_output", true))
		attrs = append(attrs, attribute.Int("gibson.component.build_output_length", len(result.BuildOutput)))
	}

	return attrs
}

// UninstallResultAttributes creates OpenTelemetry attributes from an UninstallResult.
// Includes uninstall metrics and component state before removal.
func UninstallResultAttributes(result *UninstallResult) []attribute.KeyValue {
	if result == nil {
		return []attribute.KeyValue{}
	}

	attrs := []attribute.KeyValue{
		attribute.String(AttrComponentName, result.Name),
		attribute.String(AttrComponentKind, result.Kind.String()),
		attribute.Bool("gibson.component.was_running", result.WasRunning),
		attribute.Bool("gibson.component.was_stopped", result.WasStopped),
		attribute.Float64("gibson.component.uninstall_duration_ms", float64(result.Duration.Milliseconds())),
	}

	if result.Path != "" {
		attrs = append(attrs, attribute.String("gibson.component.path", result.Path))
	}

	return attrs
}

// LifecycleAttributes creates OpenTelemetry attributes for lifecycle operations.
// Includes operation-specific metadata like port assignments and startup times.
func LifecycleAttributes(operation string, port int, duration int64) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("gibson.component.operation", operation),
	}

	if port > 0 {
		attrs = append(attrs, attribute.Int(AttrComponentPort, port))
	}

	if duration > 0 {
		attrs = append(attrs, attribute.Int64("gibson.component.operation_duration_ms", duration))
	}

	return attrs
}

// ErrorAttributes creates OpenTelemetry attributes for component errors.
// Includes error details and context for debugging.
func ErrorAttributes(err error, operation string) []attribute.KeyValue {
	if err == nil {
		return []attribute.KeyValue{}
	}

	attrs := []attribute.KeyValue{
		attribute.Bool("error", true),
		attribute.String("error.message", err.Error()),
	}

	if operation != "" {
		attrs = append(attrs, attribute.String("gibson.component.failed_operation", operation))
	}

	// Add component-specific error details if it's a ComponentError
	if compErr, ok := err.(*ComponentError); ok {
		attrs = append(attrs,
			attribute.String("error.code", string(compErr.Code)),
			attribute.String("error.type", "ComponentError"),
		)

		if compErr.Component != "" {
			attrs = append(attrs, attribute.String(AttrComponentName, compErr.Component))
		}
	}

	return attrs
}
