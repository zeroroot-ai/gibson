package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	sdkauth "github.com/zero-day-ai/sdk/auth"
)

var (
	// tracer is the OpenTelemetry tracer for authentication spans.
	tracer = otel.Tracer("gibson.auth")
)

// ---------------------------------------------------------------------------
// AgentAuthClaims — verified claims from an Agent Auth JWT
//
// Defined here (rather than importing agentauth) to avoid an import cycle.
// The daemon wires an AgentJWTValidator adapter that wraps agentauth.JWTVerifier
// and returns *AgentAuthClaims so the auth interceptor never imports agentauth.
// ---------------------------------------------------------------------------

// AgentAuthClaims contains the verified claims from an agent+jwt or host+jwt token.
// All fields are guaranteed non-empty after successful verification, EXCEPT
// ComponentScope which is empty on host+jwt tokens (scope is agent-level).
type AgentAuthClaims struct {
	// AgentID is the agent that presented this token (JWT sub).
	AgentID string

	// HostID is the host the agent is registered under (JWT iss).
	HostID string

	// TenantID is sourced from the agent's store record (not the JWT).
	TenantID string

	// OwnerUserID is the user who owns this agent (sourced from the store).
	// The interceptor sets Identity.Subject to this value so that the FGA
	// interceptor checks the owner's permissions, not the agent's.
	OwnerUserID string

	// ComponentScope is the FGA component identifier bound to this agent at
	// registration. The adapter extracts the value from the agent+jwt's
	// component_scope payload claim. Host+jwt tokens (used only for
	// registration, not daemon RPCs) leave this empty. The FGA interceptor
	// denies any daemon RPC that comes in on the agent-auth path without
	// ComponentScope populated (spec R2 AC 5).
	ComponentScope string

	// ExpiresAt is when the token expires (JWT exp).
	ExpiresAt time.Time
}

// contextKey is a private type to avoid collisions on context values.
type contextKey string

// componentScopeContextKey is the context key used to carry the verified
// agent component_scope through the request pipeline. Set by
// UnaryAuthInterceptor during agent-auth routing; consumed by the FGA
// interceptor for the second (component-scope) Check.
const componentScopeContextKey contextKey = "agent-component-scope"

// ContextWithComponentScope attaches scope to ctx. Returns ctx unchanged if
// scope is empty — use only with the verified value from AgentAuthClaims.
func ContextWithComponentScope(ctx context.Context, scope string) context.Context {
	if scope == "" {
		return ctx
	}
	return context.WithValue(ctx, componentScopeContextKey, scope)
}

// ComponentScopeFromContext returns the agent's component_scope (e.g.,
// "component:agent-abc123") if the request was authenticated via agent-auth,
// or empty string otherwise. The FGA interceptor branches on this value to
// run the R2 two-check path (owner + component).
func ComponentScopeFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(componentScopeContextKey).(string); ok {
		return v
	}
	return ""
}

// ---------------------------------------------------------------------------
// Internal validator interfaces
//
// These narrow interfaces allow the concrete validator types to be used in
// production code while enabling lightweight mocks in unit tests. All four
// concrete types satisfy their respective interface automatically.
// ---------------------------------------------------------------------------

// apiKeyValidatorIface is the narrow contract for API key auth.
type apiKeyValidatorIface interface {
	Authenticate(ctx context.Context, token string) (*Identity, error)
}

// AgentJWTValidator is the interface the interceptor uses to verify Agent Auth JWTs.
//
// The daemon wires this with an adapter that wraps agentauth.JWTVerifier and
// converts agentauth.AgentClaims → auth.AgentAuthClaims so that the auth
// package never needs to import agentauth directly.
//
// Exported so the daemon package can implement the adapter.
type AgentJWTValidator interface {
	VerifyAgentJWT(ctx context.Context, tokenStr, expectedAud string) (*AgentAuthClaims, error)
}

// betterAuthValidatorIface is the narrow contract for Better Auth HMAC-SHA256 tokens.
type betterAuthValidatorIface interface {
	Authenticate(ctx context.Context, token string) (*Identity, error)
}

// ---------------------------------------------------------------------------
// Agent Auth JWT header detection (no crypto, no external deps)
// ---------------------------------------------------------------------------

// jwtHeader is the minimal JOSE header decoded during fast-path detection.
type jwtHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

// IsAgentAuthJWT reports whether token looks like an Agent Auth JWT by inspecting
// only the header. Returns true for tokens whose typ is "agent+jwt" or "host+jwt"
// with alg "EdDSA".
//
// This is a fast structural check — it does NOT verify the signature or any
// claims. A true result only means the token should be routed to the Agent Auth
// verification path.
//
// Duplicated from agentauth.IsAgentAuthJWT to avoid an import cycle.
func IsAgentAuthJWT(token string) bool {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var hdr jwtHeader
	if err := json.Unmarshal(b, &hdr); err != nil {
		return false
	}
	return (hdr.Typ == "agent+jwt" || hdr.Typ == "host+jwt") && hdr.Alg == "EdDSA"
}

// ---------------------------------------------------------------------------
// UnaryAuthInterceptor — 4-path routing
// ---------------------------------------------------------------------------

// UnaryAuthInterceptor returns a gRPC unary interceptor that authenticates
// requests using one of four methods:
//
//  1. SPIFFE peer cert SAN → spiffeToIdentity (TLS peer cert, no token)
//  2. gsk_ prefix          → APIKeyAuthenticator (Postgres lookup)
//  3. agent+jwt            → AgentJWTValidator (Ed25519 verify)
//  4. Otherwise            → BetterAuthValidator (HMAC-SHA256)
//
// Agent Auth JWTs set Identity.Subject to the agent's owner user ID so that the
// downstream FGA interceptor checks the owner's permissions, not the agent's.
//
// The trust_localhost bypass in AuthConfig creates a synthetic platform-operator
// identity for requests from 127.0.0.1 or ::1 without requiring a token.
func UnaryAuthInterceptor(
	apiKeys *APIKeyAuthenticator,
	agentJWT AgentJWTValidator,
	ba *BetterAuthValidator,
	cfg *AuthConfig,
	logger *slog.Logger,
) grpc.UnaryServerInterceptor {
	return buildUnaryInterceptor(apiKeys, agentJWT, ba, cfg, logger)
}

// buildUnaryInterceptor constructs the interceptor from the narrow interfaces
// so that unit tests can supply lightweight mocks.
func buildUnaryInterceptor(
	apiKeys apiKeyValidatorIface,
	agentJWT AgentJWTValidator,
	ba betterAuthValidatorIface,
	cfg *AuthConfig,
	logger *slog.Logger,
) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, span := tracer.Start(ctx, "gibson.auth.authenticate",
			oteltrace.WithSpanKind(oteltrace.SpanKindServer),
			oteltrace.WithAttributes(
				attribute.String("rpc.method", info.FullMethod),
				attribute.String("rpc.service", "gibson"),
				attribute.String("auth.mode", cfg.Mode),
			),
		)
		defer span.End()

		mode := cfg.Mode

		if mode == "" || mode == "disabled" {
			span.SetAttributes(attribute.String("auth.result", "rejected_no_config"))
			return nil, status.Error(grpccodes.Unauthenticated, "authentication required")
		}

		// Localhost bypass — must come before token extraction.
		if cfg.TrustLocalhost {
			if identity, bypassed, peerAddr := checkLocalhostBypassWithAddr(ctx, logger, info.FullMethod); bypassed {
				span.SetAttributes(
					attribute.String("auth.result", "localhost_bypass"),
					attribute.String("auth.subject", identity.Subject),
					attribute.String("auth.issuer", identity.Issuer),
				)
				logLocalhostBypass(ctx, logger, info.FullMethod, peerAddr)
				ctx = ContextWithIdentity(ctx, identity)
				ctx = injectTenant(ctx, identity, cfg, mode, span)
				return handler(ctx, req)
			}
		}

		// Path 1: SPIFFE — check TLS peer cert SAN before any token extraction.
		// In-cluster workloads present mTLS with a SPIFFE SVID; no bearer token needed.
		if spiffeID, ok := extractSPIFFEID(ctx); ok {
			identity, err := spiffeToIdentity(spiffeID)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "unknown spiffe id")
				span.SetAttributes(attribute.String("auth.result", "failure"))
				logAuthFailure(ctx, logger, info.FullMethod, err.Error())
				return nil, toGRPCStatus(err)
			}
			logAuthSuccess(ctx, logger, info.FullMethod, identity)
			setAuthSpanAttributes(span, identity)
			ctx = ContextWithIdentity(ctx, identity)
			ctx = injectTenant(ctx, identity, cfg, mode, span)
			return handler(ctx, req)
		}

		token, err := extractBearerToken(ctx)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "missing bearer token")
			span.SetAttributes(attribute.String("auth.result", "missing_token"))
			logMissingToken(ctx, logger, info.FullMethod)
			return nil, status.Error(grpccodes.Unauthenticated, "missing bearer token")
		}

		identity, err := routeAuth(ctx, token, info.FullMethod, apiKeys, agentJWT, ba)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "authentication failed")
			span.SetAttributes(attribute.String("auth.result", "failure"))
			logAuthFailure(ctx, logger, info.FullMethod, err.Error())
			return nil, toGRPCStatus(err)
		}

		logAuthSuccess(ctx, logger, info.FullMethod, identity)
		setAuthSpanAttributes(span, identity)
		ctx = ContextWithIdentity(ctx, identity)
		ctx = injectTenant(ctx, identity, cfg, mode, span)
		ctx = injectComponentScope(ctx, identity)
		if mode == "saas" && TenantFromContext(ctx) == "" {
			span.SetAttributes(attribute.String("auth.result", "no_tenant"))
			logMissingTenant(ctx, logger, info.FullMethod, identity)
			return nil, status.Error(grpccodes.PermissionDenied, "no tenant identifier found in token")
		}

		return handler(ctx, req)
	}
}

// injectComponentScope pulls the component_scope claim out of an agent-auth
// identity and attaches it to ctx. No-op for non-agent-auth identities. The
// FGA interceptor's R2 two-check path consumes the context value via
// ComponentScopeFromContext.
func injectComponentScope(ctx context.Context, identity *Identity) context.Context {
	if identity == nil || identity.Issuer != "agent-auth" {
		return ctx
	}
	return ContextWithComponentScope(ctx, agentScopeFromIdentity(identity))
}

// ---------------------------------------------------------------------------
// StreamAuthInterceptor — same 4-path logic for streaming RPCs
// ---------------------------------------------------------------------------

// StreamAuthInterceptor returns a gRPC stream interceptor that authenticates
// requests using the same routing logic as UnaryAuthInterceptor.
// Authentication is performed once when the stream is established; the
// authenticated Identity and Tenant are injected into the stream context for
// the duration of the stream.
func StreamAuthInterceptor(
	apiKeys *APIKeyAuthenticator,
	agentJWT AgentJWTValidator,
	ba *BetterAuthValidator,
	cfg *AuthConfig,
	logger *slog.Logger,
) grpc.StreamServerInterceptor {
	return buildStreamInterceptor(apiKeys, agentJWT, ba, cfg, logger)
}

// buildStreamInterceptor constructs the stream interceptor from the narrow
// interfaces so that unit tests can supply lightweight mocks.
func buildStreamInterceptor(
	apiKeys apiKeyValidatorIface,
	agentJWT AgentJWTValidator,
	ba betterAuthValidatorIface,
	cfg *AuthConfig,
	logger *slog.Logger,
) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()

		ctx, span := tracer.Start(ctx, "gibson.auth.authenticate.stream",
			oteltrace.WithSpanKind(oteltrace.SpanKindServer),
			oteltrace.WithAttributes(
				attribute.String("rpc.method", info.FullMethod),
				attribute.String("rpc.service", "gibson"),
				attribute.Bool("rpc.is_streaming", true),
				attribute.String("auth.mode", cfg.Mode),
			),
		)
		defer span.End()

		mode := cfg.Mode

		if mode == "" || mode == "disabled" {
			span.SetAttributes(attribute.String("auth.result", "rejected_no_config"))
			return status.Error(grpccodes.Unauthenticated, "authentication required")
		}

		if cfg.TrustLocalhost {
			if identity, bypassed, peerAddr := checkLocalhostBypassWithAddr(ctx, logger, info.FullMethod); bypassed {
				span.SetAttributes(
					attribute.String("auth.result", "localhost_bypass"),
					attribute.String("auth.subject", identity.Subject),
					attribute.String("auth.issuer", identity.Issuer),
				)
				logLocalhostBypass(ctx, logger, info.FullMethod, peerAddr)
				ctx = ContextWithIdentity(ctx, identity)
				ctx = injectTenant(ctx, identity, cfg, mode, span)
				return handler(srv, &authenticatedServerStream{ServerStream: ss, ctx: ctx})
			}
		}

		// Path 1: SPIFFE — check TLS peer cert SAN before any token extraction.
		if spiffeID, ok := extractSPIFFEID(ctx); ok {
			identity, err := spiffeToIdentity(spiffeID)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "unknown spiffe id")
				span.SetAttributes(attribute.String("auth.result", "failure"))
				logAuthFailure(ctx, logger, info.FullMethod, err.Error())
				return toGRPCStatus(err)
			}
			logAuthSuccess(ctx, logger, info.FullMethod, identity)
			setAuthSpanAttributes(span, identity)
			ctx = ContextWithIdentity(ctx, identity)
			ctx = injectTenant(ctx, identity, cfg, mode, span)
			return handler(srv, &authenticatedServerStream{ServerStream: ss, ctx: ctx})
		}

		token, err := extractBearerToken(ctx)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "missing bearer token")
			span.SetAttributes(attribute.String("auth.result", "missing_token"))
			logMissingToken(ctx, logger, info.FullMethod)
			return status.Error(grpccodes.Unauthenticated, "missing bearer token")
		}

		identity, err := routeAuth(ctx, token, info.FullMethod, apiKeys, agentJWT, ba)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "authentication failed")
			span.SetAttributes(attribute.String("auth.result", "failure"))
			logAuthFailure(ctx, logger, info.FullMethod, err.Error())
			return toGRPCStatus(err)
		}

		logAuthSuccess(ctx, logger, info.FullMethod, identity)
		setAuthSpanAttributes(span, identity)
		ctx = ContextWithIdentity(ctx, identity)
		ctx = injectTenant(ctx, identity, cfg, mode, span)
		ctx = injectComponentScope(ctx, identity)
		if mode == "saas" && TenantFromContext(ctx) == "" {
			span.SetAttributes(attribute.String("auth.result", "no_tenant"))
			logMissingTenant(ctx, logger, info.FullMethod, identity)
			return status.Error(grpccodes.PermissionDenied, "no tenant identifier found in token")
		}

		return handler(srv, &authenticatedServerStream{ServerStream: ss, ctx: ctx})
	}
}

// ---------------------------------------------------------------------------
// 4-path routing core
// ---------------------------------------------------------------------------

// routeAuth dispatches the token to the correct validator based on its shape.
//
// Detection order (each check is O(1) before any crypto):
//  1. "gsk_" prefix    → API key path (Postgres hash lookup)
//  2. IsAgentAuthJWT() → Agent Auth JWT path (Ed25519, header decode only)
//  3. default          → Better Auth path (HMAC-SHA256)
//
// SPIFFE auth is handled upstream in the interceptor (before token extraction)
// and never reaches this function.
//
// There is no fallthrough: each branch either returns an Identity or an error.
// When a validator is nil the token is treated as invalid for that path to
// prevent a nil dereference.
func routeAuth(
	ctx context.Context,
	token string,
	fullMethod string,
	apiKeys apiKeyValidatorIface,
	agentJWT AgentJWTValidator,
	ba betterAuthValidatorIface,
) (*Identity, error) {
	switch {
	case strings.HasPrefix(token, "gsk_"):
		if apiKeys == nil {
			return nil, ErrInvalidToken(fmt.Errorf("API key authentication not configured"))
		}
		return apiKeys.Authenticate(ctx, token)

	case IsAgentAuthJWT(token):
		if agentJWT == nil {
			return nil, ErrInvalidToken(fmt.Errorf("agent auth JWT verification not configured"))
		}
		claims, err := agentJWT.VerifyAgentJWT(ctx, token, fullMethod)
		if err != nil {
			return nil, err
		}
		return agentClaimsToIdentity(claims), nil

	default:
		if ba == nil {
			return nil, ErrInvalidToken(fmt.Errorf("Better Auth validation not configured"))
		}
		return ba.Authenticate(ctx, token)
	}
}

// agentClaimsToIdentity converts verified AgentAuthClaims into a Gibson Identity.
//
// The Identity's Subject is set to the agent's owner user ID (not the agent ID)
// so that the downstream FGA interceptor checks the owner's permissions. The
// agent inherits its owner's access transparently. Agent-specific metadata
// (agent_id, host_id) is preserved in Claims for audit purposes.
func agentClaimsToIdentity(claims *AgentAuthClaims) *Identity {
	return &Identity{
		Identity: sdkauth.Identity{
			Subject:         claims.OwnerUserID,
			Issuer:          "agent-auth",
			ExpiresAt:       claims.ExpiresAt,
			AuthenticatedAt: time.Now(),
			Claims: map[string]any{
				"agent_id":        claims.AgentID,
				"host_id":         claims.HostID,
				"component_scope": claims.ComponentScope,
			},
		},
		Tenants: []string{claims.TenantID},
	}
}

// agentScopeFromIdentity pulls the component_scope claim (set by
// agentClaimsToIdentity) back out of the Identity.Claims map. Returns empty
// for non-agent-auth identities — the downstream FGA interceptor checks
// Identity.Issuer before using this.
func agentScopeFromIdentity(ident *Identity) string {
	if ident == nil || ident.Claims == nil {
		return ""
	}
	if v, ok := ident.Claims["component_scope"].(string); ok {
		return v
	}
	return ""
}

// ---------------------------------------------------------------------------
// Tenant injection helper
// ---------------------------------------------------------------------------

// injectTenant extracts the tenant from the identity and injects it into the
// context. The behaviour depends on the auth mode:
//
//   - saas: inject if found; caller must reject if empty after this call.
//   - enterprise: inject if found; fall back to DefaultTenant.
//   - dev (or other): inject DefaultTenant if configured.
func injectTenant(ctx context.Context, identity *Identity, cfg *AuthConfig, mode string, span oteltrace.Span) context.Context {
	switch mode {
	case "saas", "enterprise":
		tenant := extractAndValidateTenant(ctx, identity, cfg, span)
		if tenant != "" {
			ctx = ContextWithTenant(ctx, tenant)
		}
	default:
		if cfg.DefaultTenant != "" {
			ctx = ContextWithTenant(ctx, cfg.DefaultTenant)
			span.SetAttributes(attribute.String("auth.tenant", cfg.DefaultTenant))
		}
	}
	return ctx
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// convertToSDKIdentity converts a Gibson Core Identity to an SDK Identity.
func convertToSDKIdentity(coreIdentity *Identity) *sdkauth.Identity {
	if coreIdentity == nil {
		return nil
	}
	return &coreIdentity.Identity
}

// extractAndValidateTenant extracts the tenant ID from the identity and validates it.
//
// Returns:
//   - The tenant ID if found in identity claims
//   - The default tenant if configured and no tenant in claims
//   - Empty string if no tenant found and no default configured
func extractAndValidateTenant(ctx context.Context, identity *Identity, cfg *AuthConfig, span oteltrace.Span) string {
	tenant := ExtractTenantFromIdentity(identity, cfg.TenantClaim)

	if tenant != "" {
		span.SetAttributes(
			attribute.String("auth.tenant", tenant),
			attribute.String("auth.tenant_source", "token_claim"),
		)
		return tenant
	}

	if cfg.DefaultTenant != "" {
		span.SetAttributes(
			attribute.String("auth.tenant", cfg.DefaultTenant),
			attribute.String("auth.tenant_source", "default"),
		)
		return cfg.DefaultTenant
	}

	return ""
}

// Note: the in-handler role/permission helpers were removed as part of the
// declarative-rbac-framework spec. All RPC authorization is now enforced
// by the single RPCAuthzInterceptor via permissions.yaml. Handlers do not
// perform in-handler role checks any more.

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

	authHeader := authHeaders[0]

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", errInvalidToken
	}

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

	addr := p.Addr.String()

	isLocalhost := strings.HasPrefix(addr, "127.0.0.1:") ||
		strings.HasPrefix(addr, "[::1]:") ||
		strings.HasPrefix(addr, "localhost:")

	if !isLocalhost {
		return nil, false, ""
	}

	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject:         "localhost",
			Issuer:          "internal",
			Email:           "",
			Groups:          []string{"localhost"},
			Claims:          map[string]any{"source": "localhost"},
			ExpiresAt:       timeNever(),
			AuthenticatedAt: timeNow(),
		},
		Roles:        []string{"platform-operator"},
		Permissions:  []Permission{{Action: "*", Resource: "*", Scope: "*"}},
		Capabilities: []string{"*"},
	}

	return identity, true, addr
}

// authenticatedServerStream wraps grpc.ServerStream to override the context.
type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the authenticated context.
func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}

// logPermissionDeniedFromContext logs a permission denied event using the default logger.
func logPermissionDeniedFromContext(ctx context.Context, identity *Identity, action, resource string) {
	logger := slog.Default()
	logPermissionDenied(ctx, logger, identity, action, resource)
}

// setAuthSpanAttributes sets the standard auth success attributes on a span.
func setAuthSpanAttributes(span oteltrace.Span, identity *Identity) {
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
