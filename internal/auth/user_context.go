package auth

import (
	"context"
	"slices"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// actingUserContextKey is the unexported context key for the acting user ID.
// Using a private type prevents key collisions with other packages.
type actingUserContextKey struct{}

var actingUserCtxKey = actingUserContextKey{}

// UserContextInterceptor returns a gRPC unary interceptor that extracts acting
// user context from gRPC metadata when the caller has the platform-service role.
//
// The dashboard authenticates as itself via SPIFFE mTLS (platform-service role)
// and forwards the authenticated user's identity as metadata:
//   - x-gibson-user-id — the end user's ID from the Better Auth session
//   - x-gibson-tenant  — the user's active tenant
//
// Callers without the platform-service role have their x-gibson-user-id metadata
// silently ignored. This prevents non-dashboard callers from spoofing user context.
//
// Install this interceptor AFTER the auth interceptor (which populates Identity)
// and BEFORE the FGA authorization interceptor (which reads tenant context).
func UserContextInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = extractUserContext(ctx)
		return handler(ctx, req)
	}
}

// UserContextStreamInterceptor returns a gRPC stream interceptor that performs
// the same acting user extraction as UserContextInterceptor.
func UserContextStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := extractUserContext(ss.Context())
		return handler(srv, &userContextServerStream{ServerStream: ss, ctx: ctx})
	}
}

// extractUserContext reads x-gibson-user-id and x-gibson-tenant from gRPC
// metadata and injects them into the context if the caller has platform-service.
func extractUserContext(ctx context.Context) context.Context {
	identity, ok := GibsonIdentityFromContext(ctx)
	if !ok || identity == nil {
		return ctx
	}

	// Only platform-service callers (dashboard) may forward user context.
	if !hasRole(identity, "platform-service") {
		return ctx
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	if userIDs := md.Get("x-gibson-user-id"); len(userIDs) > 0 && userIDs[0] != "" {
		ctx = ContextWithActingUser(ctx, userIDs[0])
	}

	if tenantIDs := md.Get("x-gibson-tenant"); len(tenantIDs) > 0 && tenantIDs[0] != "" {
		ctx = ContextWithTenant(ctx, tenantIDs[0])
	}

	return ctx
}

// hasRole reports whether the identity has the given role.
func hasRole(identity *Identity, role string) bool {
	return slices.Contains(identity.Roles, role)
}

// ContextWithActingUser stores an acting user ID in the context. The acting
// user is the end user on whose behalf a platform-service caller is acting.
//
// Use ActingUserFromContext to retrieve the value downstream.
func ContextWithActingUser(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, actingUserCtxKey, userID)
}

// ActingUserFromContext returns the acting user ID stored in the context and
// true if present, or empty string and false if not set.
//
// Handlers that need to scope data to the end user (list missions, findings,
// etc.) should check this first and fall back to identity.Subject:
//
//	actingUser, ok := auth.ActingUserFromContext(ctx)
//	if !ok {
//	    identity, _ := auth.GibsonIdentityFromContext(ctx)
//	    actingUser = identity.Subject
//	}
func ActingUserFromContext(ctx context.Context) (string, bool) {
	if v, ok := ctx.Value(actingUserCtxKey).(string); ok && v != "" {
		return v, true
	}
	return "", false
}

// userContextServerStream wraps a grpc.ServerStream to carry an enriched context.
type userContextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *userContextServerStream) Context() context.Context { return s.ctx }
