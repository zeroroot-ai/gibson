// Package auth provides authentication for Gibson's gRPC server.
//
// This package implements authentication with support for:
//   - API key tokens (gsk_-prefixed, Postgres-backed)
//   - Kubernetes ServiceAccount token validation via TokenReview API
//   - Better Auth HMAC-SHA256 session tokens from the dashboard
//   - Agent Auth JWTs (Task 10)
//
// # Architecture
//
// The auth package is organized into modular components:
//
//   - auth.go: Core Authenticator interface and Identity types
//   - config.go: Configuration types for YAML/Viper integration
//   - apikey.go: API key authentication (gsk_-prefixed tokens, Postgres-backed)
//   - better_auth.go: Better Auth HMAC-SHA256 session token validation
//   - k8s.go: Kubernetes TokenReview validation
//   - jwks.go: JWKS caching with TTL and background refresh
//   - roles.go: Role binding evaluation and permission computation
//   - interceptor.go: gRPC interceptors for authentication enforcement
//   - errors.go: Auth-specific errors with gRPC status codes
//   - metrics.go: Prometheus metrics for observability
//
// # Authentication Flow
//
//  1. gRPC interceptor extracts Bearer token from metadata
//  2. Token routed to the appropriate authenticator based on token format
//  3. Token validated and claims extracted
//  4. Identity injected into request context
//  5. Handlers use IdentityFromContext() to access authenticated identity
//
// # Configuration
//
// Authentication is configured in gibson.yaml:
//
//	auth:
//	  mode: enterprise
//	  trust_localhost: false
//	  clock_skew: 30s
//	  kubernetes:
//	    enabled: true
//	  better_auth:
//	    enabled: true
//	    secret: ${BETTER_AUTH_SECRET}
//
// # Usage
//
// Authentication is enforced via gRPC interceptors:
//
//	// In daemon gRPC server setup
//	srv := grpc.NewServer(
//	    grpc.UnaryInterceptor(auth.UnaryAuthInterceptor(authenticator, &cfg.Auth, logger)),
//	    grpc.StreamInterceptor(auth.StreamAuthInterceptor(authenticator, &cfg.Auth, logger)),
//	)
//
// Authorization is enforced by the RPCAuthzInterceptor via permissions.yaml,
// NOT by per-handler checks. Handlers read the authenticated identity from
// context for data-scoping and audit purposes only:
//
//	func (s *server) ExecuteMission(ctx context.Context, req *pb.Request) (*pb.Response, error) {
//	    identity, ok := auth.GibsonIdentityFromContext(ctx)
//	    if !ok {
//	        return nil, status.Error(codes.Unauthenticated, "not authenticated")
//	    }
//	    // identity.Subject for audit, identity.Roles as data, etc.
//	}
//
// # Thread Safety
//
// All authenticator implementations are safe for concurrent use.
// The JWKS cache uses sync.RWMutex for thread-safe access.
// Identity instances are immutable after creation.
//
// # Security
//
// Tokens are NEVER logged, even at debug level.
// Clock skew tolerance is configurable (default 30s).
package auth
