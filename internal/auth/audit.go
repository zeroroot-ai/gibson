package auth

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/peer"
)

// AuditEvent represents an authentication or authorization event for logging.
//
// Consumed by both the existing auth interceptor (auth_success, auth_failure,
// missing_token, localhost_bypass events) AND the new RPC authz interceptor
// (authz_allow, authz_deny events from the declarative-rbac-framework spec).
// All events flow through logAuditEvent below, which routes them to the same
// slog pipeline used for every other audit event in Gibson, so Loki/Grafana
// queries work unchanged.
type AuditEvent struct {
	// Timestamp is when the event occurred.
	Timestamp time.Time

	// EventType is the type of audit event.
	// Examples: "auth_success", "auth_failure", "missing_token",
	// "localhost_bypass", "authz_allow", "authz_deny".
	EventType string

	// Method is the gRPC method being called.
	Method string

	// Subject is the authenticated subject (if available).
	Subject string

	// Issuer is the token issuer (if available).
	Issuer string

	// TenantID is the tenant identifier (if available).
	TenantID string

	// Roles are the resolved roles (if available).
	Roles []string

	// ClientIP is the client's IP address.
	ClientIP string

	// TraceID is the OpenTelemetry trace ID for correlation.
	TraceID string

	// PeerAddr is the remote peer address.
	PeerAddr string

	// Reason provides additional context for failures.
	Reason string

	// Action and Resource are populated for permission checks.
	Action   string
	Resource string

	// Success indicates whether the operation succeeded.
	Success bool

	// PermissionRequired names the specific permission the RPC interceptor
	// evaluated (e.g. "tenants:provision"). Populated only for authz_allow
	// and authz_deny events.
	PermissionRequired string

	// PermissionsGranted is the caller's full effective permission set at
	// the moment of the decision. Populated only for authz_allow and
	// authz_deny events so operators can see exactly what the caller held.
	PermissionsGranted []string
}

// logAuditEvent logs a structured audit event.
//
// This function provides consistent audit logging across all authentication
// and authorization events in the interceptor.
func logAuditEvent(ctx context.Context, logger *slog.Logger, event *AuditEvent) {
	if logger == nil {
		logger = slog.Default()
	}

	// Extract peer address from context if not provided
	if event.PeerAddr == "" && event.ClientIP == "" {
		if p, ok := peer.FromContext(ctx); ok {
			event.PeerAddr = p.Addr.String()
			if event.ClientIP == "" {
				event.ClientIP = extractIPFromPeerAddr(p.Addr.String())
			}
		}
	}

	// Extract trace ID from context if not provided
	if event.TraceID == "" {
		if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
			event.TraceID = span.SpanContext().TraceID().String()
		}
	}

	// Extract tenant ID from context if not provided
	if event.TenantID == "" {
		event.TenantID = TenantFromContext(ctx)
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Build log attributes
	attrs := []any{
		"event_type", event.EventType,
		"timestamp", event.Timestamp,
		"success", event.Success,
	}

	// Add trace ID if available
	if event.TraceID != "" {
		attrs = append(attrs, "trace_id", event.TraceID)
	}

	// Add method if available
	if event.Method != "" {
		attrs = append(attrs, "method", event.Method)
	}

	// Add client IP if available
	if event.ClientIP != "" {
		attrs = append(attrs, "client_ip", event.ClientIP)
	}

	// Add peer address if available
	if event.PeerAddr != "" {
		attrs = append(attrs, "peer_addr", event.PeerAddr)
	}

	// Add optional fields
	if event.Subject != "" {
		attrs = append(attrs, "subject", event.Subject)
	}
	if event.Issuer != "" {
		attrs = append(attrs, "issuer", event.Issuer)
	}
	if event.TenantID != "" {
		attrs = append(attrs, "tenant_id", event.TenantID)
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
	if event.PermissionRequired != "" {
		attrs = append(attrs, "permission_required", event.PermissionRequired)
	}
	if len(event.PermissionsGranted) > 0 {
		attrs = append(attrs, "permissions_granted", event.PermissionsGranted)
	}

	// Log at appropriate level based on event type. authz_allow follows the
	// auth_success Info routing; authz_deny follows the auth_failure Warn
	// routing — so existing Loki/Grafana log-level filters keep working
	// without configuration changes.
	switch event.EventType {
	case "auth_success", "localhost_bypass", "authz_allow":
		logger.Info("authentication audit event", attrs...)
	case "auth_failure", "missing_token", "permission_denied", "authz_deny":
		logger.Warn("authentication audit event", attrs...)
	default:
		logger.Info("authentication audit event", attrs...)
	}
}

// extractIPFromPeerAddr extracts the IP address from a peer address string.
// Handles formats like "127.0.0.1:port" and "[::1]:port".
func extractIPFromPeerAddr(addr string) string {
	// Find the last colon to separate IP from port
	lastColon := -1
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			lastColon = i
			break
		}
	}

	if lastColon == -1 {
		return addr
	}

	ip := addr[:lastColon]

	// Remove brackets for IPv6
	if len(ip) > 0 && ip[0] == '[' {
		ip = ip[1:]
	}
	if len(ip) > 0 && ip[len(ip)-1] == ']' {
		ip = ip[:len(ip)-1]
	}

	return ip
}

// LogAuthSuccess logs a successful authentication event with audit trail.
//
// This function should be called after successful token validation to create
// an audit record. It automatically extracts the trace ID from the context
// and includes tenant information if available.
//
// NEVER logs token values - only metadata about the authentication.
//
// Parameters:
//   - ctx: Context with OpenTelemetry span for trace ID extraction
//   - identity: The authenticated identity (must not be nil)
//   - clientIP: The client's IP address (can be empty, will be extracted from context)
//
// Example:
//
//	identity, err := authenticator.Authenticate(ctx, token)
//	if err == nil {
//	    auth.LogAuthSuccess(ctx, identity, "192.168.1.100")
//	}
func LogAuthSuccess(ctx context.Context, identity *Identity, clientIP string) {
	if identity == nil {
		return
	}

	logAuditEvent(ctx, slog.Default(), &AuditEvent{
		EventType: "auth_success",
		Subject:   identity.Subject,
		Issuer:    identity.Issuer,
		Roles:     identity.Roles,
		ClientIP:  clientIP,
		Success:   true,
	})
}

// logAuthSuccess logs a successful authentication event (internal helper for interceptor).
func logAuthSuccess(ctx context.Context, logger *slog.Logger, method string, identity *Identity) {
	logAuditEvent(ctx, logger, &AuditEvent{
		EventType: "auth_success",
		Method:    method,
		Subject:   identity.Subject,
		Issuer:    identity.Issuer,
		Roles:     identity.Roles,
		Success:   true,
	})
}

// LogAuthFailure logs a failed authentication event with audit trail.
//
// This function should be called when token validation fails to create
// an audit record. It automatically extracts the trace ID from the context.
//
// NEVER logs token values - only metadata about the failure.
//
// Parameters:
//   - ctx: Context with OpenTelemetry span for trace ID extraction
//   - reason: The failure reason (e.g., "token expired", "invalid signature")
//   - issuer: The token issuer if known (can be empty)
//   - clientIP: The client's IP address (can be empty, will be extracted from context)
//
// Example:
//
//	_, err := authenticator.Authenticate(ctx, token)
//	if err != nil {
//	    auth.LogAuthFailure(ctx, err.Error(), "https://issuer.example.com", "192.168.1.100")
//	}
func LogAuthFailure(ctx context.Context, reason string, issuer string, clientIP string) {
	logAuditEvent(ctx, slog.Default(), &AuditEvent{
		EventType: "auth_failure",
		Reason:    reason,
		Issuer:    issuer,
		ClientIP:  clientIP,
		Success:   false,
	})
}

// logAuthFailure logs a failed authentication event (internal helper for interceptor).
func logAuthFailure(ctx context.Context, logger *slog.Logger, method, reason string) {
	logAuditEvent(ctx, logger, &AuditEvent{
		EventType: "auth_failure",
		Method:    method,
		Reason:    reason,
		Success:   false,
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

// LogPermissionDenied logs a permission denied event with audit trail.
//
// This function should be called when authorization checks fail to create
// an audit record. It automatically extracts the trace ID from the context
// and includes tenant information if available.
//
// Parameters:
//   - ctx: Context with OpenTelemetry span for trace ID extraction
//   - identity: The authenticated identity (can be nil for unauthenticated attempts)
//   - action: The attempted action (e.g., "execute", "read", "write")
//   - resource: The target resource (e.g., "mission", "finding", "agent")
//
// Example:
//
//	identity, _ := sdkauth.IdentityFromContext(ctx)
//	if !hasPermission(identity, "execute", "mission") {
//	    auth.LogPermissionDenied(ctx, coreIdentity, "execute", "mission")
//	    return status.Error(codes.PermissionDenied, "insufficient permissions")
//	}
func LogPermissionDenied(ctx context.Context, identity *Identity, action, resource string) {
	event := &AuditEvent{
		EventType: "permission_denied",
		Action:    action,
		Resource:  resource,
		Reason:    "insufficient permissions",
		Success:   false,
	}

	if identity != nil {
		event.Subject = identity.Subject
		event.Issuer = identity.Issuer
		event.Roles = identity.Roles
	}

	logAuditEvent(ctx, slog.Default(), event)
}

// logPermissionDenied logs a permission denied event (internal helper for interceptor).
func logPermissionDenied(ctx context.Context, logger *slog.Logger, identity *Identity, action, resource string) {
	event := &AuditEvent{
		EventType: "permission_denied",
		Action:    action,
		Resource:  resource,
		Reason:    "insufficient permissions",
		Success:   false,
	}

	if identity != nil {
		event.Subject = identity.Subject
		event.Issuer = identity.Issuer
		event.Roles = identity.Roles
	}

	logAuditEvent(ctx, logger, event)
}

// logMissingTenant logs a missing tenant event in SaaS mode.
func logMissingTenant(ctx context.Context, logger *slog.Logger, method string, identity *Identity) {
	event := &AuditEvent{
		EventType: "missing_tenant",
		Method:    method,
		Reason:    "no tenant identifier found in token (required in SaaS mode)",
	}

	if identity != nil {
		event.Subject = identity.Subject
		event.Issuer = identity.Issuer
	}

	logAuditEvent(ctx, logger, event)
}
