package auth

import (
	"context"
	"log/slog"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// contextKey is an unexported type for context keys to avoid collisions.
type contextKey int

const (
	// identityContextKey is the context key for storing authenticated identity.
	identityContextKey contextKey = iota
)

var (
	// tracer is the OpenTelemetry tracer for authentication spans.
	tracer = otel.Tracer("gibson.auth")
)

// UnaryAuthInterceptor creates a gRPC unary server interceptor that enforces authentication.
//
// The interceptor:
//   - Checks if authentication is enabled in config
//   - Extracts Bearer token from "authorization" metadata header
//   - Validates the token using the provided Authenticator
//   - Injects the Identity into the request context
//   - Supports localhost bypass when configured
//
// When authentication is disabled (cfg.Enabled == false), all requests pass through
// without validation.
//
// When trust_localhost is enabled and the peer address is localhost (127.0.0.1 or ::1),
// authentication is bypassed and a synthetic "localhost" identity is injected.
//
// The interceptor returns gRPC status codes:
//   - codes.Unauthenticated: Missing or invalid token
//   - codes.PermissionDenied: Valid token but insufficient permissions (handled by handlers)
//
// Thread Safety:
// The interceptor is safe for concurrent use. The Authenticator implementation
// must also be thread-safe.
//
// Parameters:
//   - auth: Authenticator implementation for token validation
//   - cfg: Authentication configuration
//   - logger: Structured logger for audit events
//
// Returns:
//   - grpc.UnaryServerInterceptor: Interceptor function for gRPC server
func UnaryAuthInterceptor(auth Authenticator, cfg *AuthConfig, logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Start tracing span for authentication
		ctx, span := tracer.Start(ctx, "gibson.auth.authenticate",
			oteltrace.WithSpanKind(oteltrace.SpanKindServer),
			oteltrace.WithAttributes(
				attribute.String("rpc.method", info.FullMethod),
				attribute.String("rpc.service", "gibson"),
				attribute.Bool("auth.enabled", cfg.Enabled),
			),
		)
		defer span.End()

		// Pass through if authentication is disabled
		if !cfg.Enabled {
			span.SetAttributes(attribute.String("auth.result", "disabled"))
			return handler(ctx, req)
		}

		// Check for localhost bypass
		if cfg.TrustLocalhost {
			if identity, bypassed, peerAddr := checkLocalhostBypassWithAddr(ctx, logger, info.FullMethod); bypassed {
				span.SetAttributes(
					attribute.String("auth.result", "localhost_bypass"),
					attribute.String("auth.subject", identity.Subject),
					attribute.String("auth.issuer", identity.Issuer),
				)
				logLocalhostBypass(ctx, logger, info.FullMethod, peerAddr)
				ctx = ContextWithIdentity(ctx, identity)
				return handler(ctx, req)
			}
		}

		// Extract Bearer token from metadata
		token, err := extractBearerToken(ctx)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "missing bearer token")
			span.SetAttributes(attribute.String("auth.result", "missing_token"))
			logMissingToken(ctx, logger, info.FullMethod)
			return nil, status.Error(grpccodes.Unauthenticated, "missing bearer token")
		}

		// Authenticate the token
		identity, err := auth.Authenticate(ctx, token)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "authentication failed")
			span.SetAttributes(attribute.String("auth.result", "failure"))
			logAuthFailure(ctx, logger, info.FullMethod, err.Error())
			return nil, toGRPCStatus(err)
		}

		// Log successful authentication with audit trail
		logAuthSuccess(ctx, logger, info.FullMethod, identity)

		// Set trace attributes for successful authentication
		span.SetStatus(codes.Ok, "authentication successful")
		span.SetAttributes(
			attribute.String("auth.result", "success"),
			attribute.String("auth.subject", identity.Subject),
			attribute.String("auth.issuer", identity.Issuer),
			attribute.StringSlice("auth.roles", identity.Roles),
			attribute.StringSlice("auth.groups", identity.Groups),
			attribute.Int("auth.permissions_count", len(identity.Permissions)),
		)
		if identity.Email != "" {
			span.SetAttributes(attribute.String("auth.email", identity.Email))
		}

		// Inject identity into context
		ctx = ContextWithIdentity(ctx, identity)

		// Continue with the request
		return handler(ctx, req)
	}
}

// StreamAuthInterceptor creates a gRPC stream server interceptor that enforces authentication.
//
// The interceptor performs the same authentication checks as UnaryAuthInterceptor but
// for streaming RPCs. Authentication is performed once when the stream is established.
//
// The authenticated Identity is injected into the stream context and is available
// for the lifetime of the stream.
//
// Thread Safety:
// The interceptor is safe for concurrent use. The Authenticator implementation
// must also be thread-safe.
//
// Parameters:
//   - auth: Authenticator implementation for token validation
//   - cfg: Authentication configuration
//   - logger: Structured logger for audit events
//
// Returns:
//   - grpc.StreamServerInterceptor: Interceptor function for gRPC server
func StreamAuthInterceptor(auth Authenticator, cfg *AuthConfig, logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()

		// Start tracing span for stream authentication
		ctx, span := tracer.Start(ctx, "gibson.auth.authenticate.stream",
			oteltrace.WithSpanKind(oteltrace.SpanKindServer),
			oteltrace.WithAttributes(
				attribute.String("rpc.method", info.FullMethod),
				attribute.String("rpc.service", "gibson"),
				attribute.Bool("rpc.is_streaming", true),
				attribute.Bool("auth.enabled", cfg.Enabled),
			),
		)
		defer span.End()

		// Pass through if authentication is disabled
		if !cfg.Enabled {
			span.SetAttributes(attribute.String("auth.result", "disabled"))
			return handler(srv, &authenticatedServerStream{ServerStream: ss, ctx: ctx})
		}

		// Check for localhost bypass
		if cfg.TrustLocalhost {
			if identity, bypassed, peerAddr := checkLocalhostBypassWithAddr(ctx, logger, info.FullMethod); bypassed {
				span.SetAttributes(
					attribute.String("auth.result", "localhost_bypass"),
					attribute.String("auth.subject", identity.Subject),
					attribute.String("auth.issuer", identity.Issuer),
				)
				logLocalhostBypass(ctx, logger, info.FullMethod, peerAddr)
				ctx = ContextWithIdentity(ctx, identity)
				return handler(srv, &authenticatedServerStream{ServerStream: ss, ctx: ctx})
			}
		}

		// Extract Bearer token from metadata
		token, err := extractBearerToken(ctx)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "missing bearer token")
			span.SetAttributes(attribute.String("auth.result", "missing_token"))
			logMissingToken(ctx, logger, info.FullMethod)
			return status.Error(grpccodes.Unauthenticated, "missing bearer token")
		}

		// Authenticate the token
		identity, err := auth.Authenticate(ctx, token)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "authentication failed")
			span.SetAttributes(attribute.String("auth.result", "failure"))
			logAuthFailure(ctx, logger, info.FullMethod, err.Error())
			return toGRPCStatus(err)
		}

		// Log successful authentication with audit trail
		logAuthSuccess(ctx, logger, info.FullMethod, identity)

		// Set trace attributes for successful authentication
		span.SetStatus(codes.Ok, "authentication successful")
		span.SetAttributes(
			attribute.String("auth.result", "success"),
			attribute.String("auth.subject", identity.Subject),
			attribute.String("auth.issuer", identity.Issuer),
			attribute.StringSlice("auth.roles", identity.Roles),
			attribute.StringSlice("auth.groups", identity.Groups),
			attribute.Int("auth.permissions_count", len(identity.Permissions)),
		)
		if identity.Email != "" {
			span.SetAttributes(attribute.String("auth.email", identity.Email))
		}

		// Inject identity into context
		ctx = ContextWithIdentity(ctx, identity)

		// Continue with the stream using the authenticated context
		return handler(srv, &authenticatedServerStream{ServerStream: ss, ctx: ctx})
	}
}

// ContextWithIdentity returns a new context with the given identity attached.
//
// The identity can be retrieved later using IdentityFromContext.
//
// This is safe to call with a nil identity, though IdentityFromContext will
// return false in that case.
func ContextWithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey, identity)
}

// IdentityFromContext extracts the authenticated identity from the context.
//
// Returns:
//   - identity: The authenticated identity if present
//   - ok: true if an identity was found in the context, false otherwise
//
// Example:
//
//	identity, ok := auth.IdentityFromContext(ctx)
//	if !ok {
//	    return status.Error(codes.Unauthenticated, "not authenticated")
//	}
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	identity, ok := ctx.Value(identityContextKey).(*Identity)
	return identity, ok
}

// RequirePermission checks if the authenticated identity has the specified permission.
//
// This is a convenience helper that combines IdentityFromContext and Identity.HasPermission.
//
// Returns:
//   - nil if the identity has the required permission
//   - gRPC UNAUTHENTICATED status if no identity is present in context
//   - gRPC PERMISSION_DENIED status if the identity lacks the required permission
//
// Example:
//
//	if err := auth.RequirePermission(ctx, "execute", "mission"); err != nil {
//	    return nil, err
//	}
func RequirePermission(ctx context.Context, action, resource string) error {
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		return status.Error(grpccodes.Unauthenticated, "not authenticated")
	}

	if !identity.HasPermission(action, resource) {
		recordPermissionDenied(ctx, action, resource)
		logPermissionDeniedFromContext(ctx, identity, action, resource)
		return status.Errorf(grpccodes.PermissionDenied,
			"insufficient permissions for %s on %s", action, resource)
	}

	return nil
}

// RequireRole checks if the authenticated identity has the specified role.
//
// This is a convenience helper that combines IdentityFromContext and Identity.HasRole.
//
// Returns:
//   - nil if the identity has the required role
//   - gRPC UNAUTHENTICATED status if no identity is present in context
//   - gRPC PERMISSION_DENIED status if the identity lacks the required role
//
// Example:
//
//	if err := auth.RequireRole(ctx, "admin"); err != nil {
//	    return nil, err
//	}
func RequireRole(ctx context.Context, role string) error {
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		return status.Error(grpccodes.Unauthenticated, "not authenticated")
	}

	if !identity.HasRole(role) {
		return status.Errorf(grpccodes.PermissionDenied,
			"missing required role: %s", role)
	}

	return nil
}

// extractBearerToken extracts the Bearer token from gRPC metadata.
//
// The token is expected in the "authorization" metadata header in the format:
// "Bearer <token>"
//
// Returns the token string without the "Bearer " prefix, or an error if not found.
func extractBearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errMissingToken
	}

	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", errMissingToken
	}

	// Use the first authorization header
	authHeader := authHeaders[0]

	// Check for Bearer prefix
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", errInvalidToken
	}

	// Extract token after "Bearer " prefix
	token := strings.TrimPrefix(authHeader, bearerPrefix)
	if token == "" {
		return "", errInvalidToken
	}

	return token, nil
}

// checkLocalhostBypassWithAddr checks if the request is from localhost and returns a synthetic identity.
//
// Returns:
//   - identity: A synthetic "localhost" identity with admin permissions
//   - bypassed: true if the request is from localhost and should bypass authentication
//   - peerAddr: The peer address (for logging)
func checkLocalhostBypassWithAddr(ctx context.Context, logger *slog.Logger, method string) (*Identity, bool, string) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, false, ""
	}

	// Extract IP address from peer
	addr := p.Addr.String()

	// Check for localhost addresses (IPv4 and IPv6)
	// Formats: "127.0.0.1:port", "[::1]:port", "localhost:port"
	isLocalhost := strings.HasPrefix(addr, "127.0.0.1:") ||
		strings.HasPrefix(addr, "[::1]:") ||
		strings.HasPrefix(addr, "localhost:")

	if !isLocalhost {
		return nil, false, ""
	}

	// Create synthetic localhost identity with admin permissions
	identity := &Identity{
		Subject:         "localhost",
		Issuer:          "internal",
		Email:           "",
		Groups:          []string{"localhost"},
		Claims:          map[string]any{"source": "localhost"},
		Roles:           []string{"admin"},
		Permissions:     []Permission{{Action: "*", Resource: "*", Scope: "*"}},
		ExpiresAt:       timeNever(),
		AuthenticatedAt: timeNow(),
	}

	return identity, true, addr
}

// authenticatedServerStream wraps grpc.ServerStream to override the context.
//
// This allows us to inject the authenticated identity into the stream context.
type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the authenticated context.
func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}

// logPermissionDeniedFromContext logs a permission denied event.
//
// This helper extracts a logger from context (if available) and logs the
// permission denied event. If no logger is available in the context, it
// uses the default slog logger.
//
// This function is called by RequirePermission when a permission check fails.
func logPermissionDeniedFromContext(ctx context.Context, identity *Identity, action, resource string) {
	// Try to extract logger from context using a well-known key
	// For now, use the default slog logger since there's no context-based logger pattern
	logger := slog.Default()

	// Log the permission denied event
	logPermissionDenied(ctx, logger, identity, action, resource)
}

// toGRPCStatus converts an authentication error to a gRPC status error.
//
// This ensures consistent error codes across the API:
//   - Token validation errors → grpccodes.Unauthenticated
//   - Permission errors → grpccodes.PermissionDenied
//   - Other errors → grpccodes.Internal
func toGRPCStatus(err error) error {
	if err == nil {
		return nil
	}

	// Map auth errors to gRPC status codes
	switch {
	case IsTokenExpiredError(err):
		return status.Error(grpccodes.Unauthenticated, "token expired")
	case IsInvalidSignatureError(err):
		return status.Error(grpccodes.Unauthenticated, "invalid token signature")
	case IsUnknownIssuerError(err):
		return status.Error(grpccodes.Unauthenticated, "unknown token issuer")
	case IsAudienceMismatchError(err):
		return status.Error(grpccodes.Unauthenticated, "invalid token audience")
	case IsInvalidTokenError(err):
		return status.Error(grpccodes.Unauthenticated, "invalid token")
	case IsMissingTokenError(err):
		return status.Error(grpccodes.Unauthenticated, "missing token")
	case IsPermissionDeniedError(err):
		return status.Error(grpccodes.PermissionDenied, err.Error())
	default:
		return status.Error(grpccodes.Internal, "authentication failed")
	}
}
