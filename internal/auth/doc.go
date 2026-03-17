// Package auth provides OpenID Connect (OIDC) authentication and authorization for Gibson.
//
// This package implements enterprise-grade authentication with support for:
//   - Multi-provider OIDC federation (Okta, Azure AD, Google Workspace)
//   - CI/CD workload identity (GitHub Actions, GitLab CI, ArgoCD)
//   - Kubernetes ServiceAccount token validation via TokenReview API
//   - Claims-to-roles mapping for flexible authorization
//   - Local development mode with static tokens
//
// # Architecture
//
// The auth package is organized into modular components:
//
//   - auth.go: Core Authenticator interface and Identity types
//   - config.go: Configuration types for YAML/Viper integration
//   - oidc.go: OIDC token validation using JWKS
//   - jwks.go: JWKS caching with TTL and background refresh
//   - claims.go: Claims extraction and normalization
//   - roles.go: Role binding evaluation and permission computation
//   - interceptor.go: gRPC interceptors for authentication enforcement
//   - k8s.go: Kubernetes TokenReview validation
//   - local.go: Static token authentication for development
//   - errors.go: Auth-specific errors with gRPC status codes
//   - metrics.go: Prometheus metrics for observability
//
// # Authentication Flow
//
//  1. gRPC interceptor extracts Bearer token from metadata
//  2. Token passed to Authenticator.Authenticate()
//  3. Authenticator matches token issuer to configuration
//  4. Token signature validated using cached JWKS
//  5. Claims extracted and mapped to Identity
//  6. Role bindings evaluated to determine permissions
//  7. Identity injected into request context
//  8. Handlers use IdentityFromContext() to access authenticated identity
//
// # Configuration
//
// Authentication is configured in gibson.yaml:
//
//	auth:
//	  enabled: true
//	  trust_localhost: false
//	  clock_skew: 30s
//	  oidc:
//	    - issuer: https://company.okta.com
//	      audience: gibson-prod
//	      jwks_ttl: 1h
//	      claims_mapping:
//	        groups: groups
//	      role_bindings:
//	        "security-team": ["mission:execute"]
//	    - issuer: https://token.actions.githubusercontent.com
//	      claims_mapping:
//	        repository: repo
//	        ref: branch
//	      role_bindings:
//	        "myorg/infra:refs/heads/main": ["mission:execute"]
//
// # Usage
//
// Authentication is enforced via gRPC interceptors:
//
//	// In daemon gRPC server setup
//	auth := auth.NewOIDCValidator(cfg.Auth)
//	srv := grpc.NewServer(
//	    grpc.UnaryInterceptor(auth.UnaryAuthInterceptor(auth, &cfg.Auth)),
//	    grpc.StreamInterceptor(auth.StreamAuthInterceptor(auth, &cfg.Auth)),
//	)
//
// Handlers access the authenticated identity from context:
//
//	func (s *server) ExecuteMission(ctx context.Context, req *pb.Request) (*pb.Response, error) {
//	    identity, ok := auth.IdentityFromContext(ctx)
//	    if !ok {
//	        return nil, status.Error(codes.Unauthenticated, "not authenticated")
//	    }
//
//	    if !identity.HasPermission("execute", "mission") {
//	        return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
//	    }
//
//	    // ... execute mission
//	}
//
// # Thread Safety
//
// All authenticator implementations are safe for concurrent use.
// The JWKS cache uses sync.RWMutex for thread-safe access.
// Identity instances are immutable after creation.
//
// # Performance
//
// JWKS responses are cached with configurable TTL (default 1 hour).
// Token validation completes in < 5ms with cached JWKS.
// Auth interceptor adds < 1ms to request latency for valid tokens.
//
// # Security
//
// Tokens are NEVER logged, even at debug level.
// JWKS fetching requires HTTPS (no plaintext allowed).
// Clock skew tolerance is configurable (default 30s).
// Audience validation prevents token misuse across services.
package auth
