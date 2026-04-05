package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errorScrubInterceptors creates unary and stream gRPC interceptors that sanitize
// error messages before they reach clients. Internal details (file paths, Go type
// names, YAML parser output, stack traces) are logged server-side and replaced
// with safe, generic messages in the gRPC status returned to callers.
//
// Position in chain: after panic recovery, before auth.
//
// Errors are classified into categories:
//   - InvalidArgument: safe prefix retained, internal details stripped
//   - Known GibsonError codes: mapped to safe user-facing messages
//   - All other codes: generic message based on gRPC code
func errorScrubInterceptors(
	logger *slog.Logger,
	meter metric.Meter,
) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor, error) {
	var scrubbedTotal metric.Int64Counter
	if meter != nil {
		var err error
		scrubbedTotal, err = meter.Int64Counter(
			"gibson.grpc.errors_scrubbed_total",
			metric.WithDescription("Total number of gRPC errors scrubbed before returning to clients"),
		)
		if err != nil {
			return nil, nil, err
		}
	}

	unary := unaryErrorScrub(logger, scrubbedTotal)
	stream := streamErrorScrub(logger, scrubbedTotal)
	return unary, stream, nil
}

// unaryErrorScrub returns a unary interceptor that scrubs error messages.
func unaryErrorScrub(logger *slog.Logger, counter metric.Int64Counter) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		resp, err = handler(ctx, req)
		if err != nil {
			err = scrubError(ctx, logger, counter, err, info.FullMethod)
		}
		return resp, err
	}
}

// streamErrorScrub returns a stream interceptor that scrubs error messages.
func streamErrorScrub(logger *slog.Logger, counter metric.Int64Counter) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		err := handler(srv, ss)
		if err != nil {
			err = scrubError(ss.Context(), logger, counter, err, info.FullMethod)
		}
		return err
	}
}

// scrubError examines a gRPC error, logs the full details server-side,
// and returns a sanitized version safe for client consumption.
func scrubError(
	ctx context.Context,
	logger *slog.Logger,
	counter metric.Int64Counter,
	err error,
	method string,
) error {
	st, ok := status.FromError(err)
	if !ok {
		// Not a gRPC status error — wrap as Internal with generic message.
		logger.Error("non-gRPC error in handler",
			"error", err.Error(),
			"grpc_method", method,
		)
		return status.Error(codes.Internal, "internal server error")
	}

	originalMsg := st.Message()

	// Check if the message needs scrubbing
	if !needsScrubbing(originalMsg) {
		return err
	}

	// Log the full unscrubbed error server-side for debugging
	logger.Warn("scrubbed error details from gRPC response",
		"grpc_method", method,
		"grpc_code", st.Code().String(),
		"original_error", originalMsg,
	)

	if counter != nil {
		counter.Add(ctx, 1,
			metric.WithAttributes(
				attribute.String("grpc_method", method),
				attribute.String("grpc_code", st.Code().String()),
			),
		)
	}

	// Build a safe message based on the gRPC code and error classification
	safeMsg := buildSafeMessage(st.Code(), originalMsg, err)
	return status.Error(st.Code(), safeMsg)
}

// needsScrubbing returns true if the error message contains internal details
// that should not be exposed to clients.
func needsScrubbing(msg string) bool {
	lower := strings.ToLower(msg)

	// File paths (absolute or temp)
	if strings.Contains(msg, "/tmp/") ||
		strings.Contains(msg, "/home/") ||
		strings.Contains(msg, "/var/") ||
		strings.Contains(msg, "/etc/") ||
		strings.Contains(msg, "/.gibson/") ||
		strings.Contains(msg, "/opt/") {
		return true
	}

	// Go type names from YAML parser (e.g., "cannot unmarshal !!str into mission.yamlNodeData")
	if strings.Contains(lower, "cannot unmarshal") ||
		strings.Contains(lower, "yaml.typeerror") ||
		strings.Contains(lower, "yaml:") {
		return true
	}

	// Internal Go struct/package names
	if strings.Contains(msg, "mission.yaml") && strings.Contains(lower, "unmarshal") {
		return true
	}

	// Stack traces or internal function references
	if strings.Contains(msg, ".go:") || strings.Contains(msg, "goroutine") {
		return true
	}

	// Internal error wrapping patterns that leak implementation
	if strings.Contains(msg, "failed to parse YAML:") ||
		strings.Contains(msg, "failed to unmarshal") ||
		strings.Contains(msg, "YAML syntax error:") ||
		strings.Contains(msg, "YAML validation failed:") {
		return true
	}

	return false
}

// buildSafeMessage produces a user-facing error message based on the gRPC code
// and the nature of the original error.
func buildSafeMessage(code codes.Code, originalMsg string, err error) string {
	// Check for known GibsonError codes to provide more helpful (but safe) messages
	var gibsonErr *types.GibsonError
	if errors.As(err, &gibsonErr) {
		return buildGibsonErrorMessage(gibsonErr)
	}

	switch code {
	case codes.InvalidArgument:
		return classifyInvalidArgument(originalMsg)
	case codes.NotFound:
		return "requested resource not found"
	case codes.PermissionDenied:
		return "permission denied"
	case codes.Unauthenticated:
		return "authentication required"
	case codes.ResourceExhausted:
		return "resource limit exceeded"
	case codes.FailedPrecondition:
		return "operation precondition not met"
	case codes.Unavailable:
		return "service temporarily unavailable"
	case codes.DeadlineExceeded:
		return "request timed out"
	case codes.Unimplemented:
		return "operation not implemented"
	default:
		return "internal server error"
	}
}

// classifyInvalidArgument produces a safe message for InvalidArgument errors
// based on what kind of validation failed.
func classifyInvalidArgument(msg string) string {
	lower := strings.ToLower(msg)

	if strings.Contains(lower, "yaml") || strings.Contains(lower, "workflow") {
		return "invalid workflow definition: check YAML syntax and required fields"
	}
	if strings.Contains(lower, "mission") {
		return "invalid mission configuration"
	}
	if strings.Contains(lower, "component") || strings.Contains(lower, "manifest") {
		return "invalid component configuration"
	}
	if strings.Contains(lower, "size") || strings.Contains(lower, "limit") {
		return "request exceeds size limit"
	}

	return "invalid request parameters"
}

// buildGibsonErrorMessage maps GibsonError codes to safe user-facing messages.
func buildGibsonErrorMessage(err *types.GibsonError) string {
	switch {
	case strings.HasPrefix(string(err.Code), "CONFIG_"):
		return "configuration error: " + err.Message
	case strings.HasPrefix(string(err.Code), "MISSION_MEMORY_"):
		return "memory operation failed"
	case strings.HasPrefix(string(err.Code), "FTS_"):
		return "search operation failed"
	case strings.HasPrefix(string(err.Code), "VECTOR_"):
		return "vector store operation failed"
	case strings.HasPrefix(string(err.Code), "CREDENTIAL_"):
		return "credential error: " + err.Message
	default:
		// Use the GibsonError's message (already controlled by us) without the cause
		return err.Message
	}
}
