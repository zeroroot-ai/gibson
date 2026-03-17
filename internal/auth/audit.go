package auth

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/peer"
)

// AuditEvent represents an authentication or authorization event for logging.
type AuditEvent struct {
	// Timestamp is when the event occurred.
	Timestamp time.Time

	// EventType is the type of audit event.
	// Examples: "auth_success", "auth_failure", "permission_denied", "localhost_bypass"
	EventType string

	// Method is the gRPC method being called.
	Method string

	// Subject is the authenticated subject (if available).
	Subject string

	// Issuer is the token issuer (if available).
	Issuer string

	// Roles are the resolved roles (if available).
	Roles []string

	// PeerAddr is the remote peer address.
	PeerAddr string

	// Reason provides additional context for failures.
	Reason string

	// Action and Resource are populated for permission checks.
	Action   string
	Resource string
}

// logAuditEvent logs a structured audit event.
//
// This function provides consistent audit logging across all authentication
// and authorization events in the interceptor.
func logAuditEvent(ctx context.Context, logger *slog.Logger, event *AuditEvent) {
	if logger == nil {
		return
	}

	// Extract peer address from context if not provided
	if event.PeerAddr == "" {
		if p, ok := peer.FromContext(ctx); ok {
			event.PeerAddr = p.Addr.String()
		}
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Build log attributes
	attrs := []any{
		"event_type", event.EventType,
		"timestamp", event.Timestamp,
		"method", event.Method,
		"peer_addr", event.PeerAddr,
	}

	// Add optional fields
	if event.Subject != "" {
		attrs = append(attrs, "subject", event.Subject)
	}
	if event.Issuer != "" {
		attrs = append(attrs, "issuer", event.Issuer)
	}
	if len(event.Roles) > 0 {
		attrs = append(attrs, "roles", event.Roles)
	}
	if event.Reason != "" {
		attrs = append(attrs, "reason", event.Reason)
	}
	if event.Action != "" {
		attrs = append(attrs, "action", event.Action)
	}
	if event.Resource != "" {
		attrs = append(attrs, "resource", event.Resource)
	}

	// Log at appropriate level based on event type
	switch event.EventType {
	case "auth_success", "localhost_bypass":
		logger.Info("authentication audit event", attrs...)
	case "auth_failure", "missing_token", "permission_denied":
		logger.Warn("authentication audit event", attrs...)
	default:
		logger.Info("authentication audit event", attrs...)
	}
}

// logAuthSuccess logs a successful authentication event.
func logAuthSuccess(ctx context.Context, logger *slog.Logger, method string, identity *Identity) {
	logAuditEvent(ctx, logger, &AuditEvent{
		EventType: "auth_success",
		Method:    method,
		Subject:   identity.Subject,
		Issuer:    identity.Issuer,
		Roles:     identity.Roles,
	})
}

// logAuthFailure logs a failed authentication event.
func logAuthFailure(ctx context.Context, logger *slog.Logger, method, reason string) {
	logAuditEvent(ctx, logger, &AuditEvent{
		EventType: "auth_failure",
		Method:    method,
		Reason:    reason,
	})
}

// logMissingToken logs a missing token event.
func logMissingToken(ctx context.Context, logger *slog.Logger, method string) {
	logAuditEvent(ctx, logger, &AuditEvent{
		EventType: "missing_token",
		Method:    method,
		Reason:    "no bearer token provided",
	})
}

// logLocalhostBypass logs a localhost bypass event.
func logLocalhostBypass(ctx context.Context, logger *slog.Logger, method string, peerAddr string) {
	logAuditEvent(ctx, logger, &AuditEvent{
		EventType: "localhost_bypass",
		Method:    method,
		Subject:   "localhost",
		Issuer:    "internal",
		PeerAddr:  peerAddr,
	})
}

// logPermissionDenied logs a permission denied event.
func logPermissionDenied(ctx context.Context, logger *slog.Logger, identity *Identity, action, resource string) {
	event := &AuditEvent{
		EventType: "permission_denied",
		Action:    action,
		Resource:  resource,
		Reason:    "insufficient permissions",
	}

	if identity != nil {
		event.Subject = identity.Subject
		event.Issuer = identity.Issuer
		event.Roles = identity.Roles
	}

	logAuditEvent(ctx, logger, event)
}
