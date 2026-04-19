package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// fgaMetricsRecorder is the narrow interface the FGA authz interceptor
// needs from the observability package. Declared locally to avoid an
// import cycle (observability imports harness → harness imports auth).
// Any type that satisfies this interface can be passed to
// NewFgaAuthzInterceptor — production passes *observability.OTelMetricsRecorder
// directly.
type fgaMetricsRecorder interface {
	RecordFgaUnavailable(ctx context.Context, method string)
	RecordAuthzDecision(ctx context.Context, decision, method, policyID string)
}

const (
	fgaAuthzTracerName = "gibson.auth.fga_authz"
	fgaAuthzSpanName   = "gibson.auth.fga_authz_check"
	agentAuthIssuer    = "agent-auth"
)

// catalogRelationToComponentGrant maps an owner-side catalog relation to its
// component-scope grant counterpart. Only catalog-gated actions (can_read,
// can_configure, can_execute) participate in component-scope narrowing; RPCs
// that check other relations (e.g., "member" on a tenant) are not subject to
// a second component-scope Check. Spec R2 AC 4.
var catalogRelationToComponentGrantMap = map[string]string{
	"can_read":      "component_read_enabled",
	"can_configure": "component_write_enabled",
	"can_execute":   "component_execute_enabled",
}

// catalogRelationToComponentGrant returns the component-scope grant relation
// corresponding to ownerRelation, and true if ownerRelation is a catalog-gated
// action. Returns "", false for non-catalog relations so the caller skips the
// second check.
func catalogRelationToComponentGrant(ownerRelation string) (string, bool) {
	v, ok := catalogRelationToComponentGrantMap[ownerRelation]
	return v, ok
}

// relationToActionClass maps any FGA relation to the three-action class
// label ("read" | "write" | "execute"). Covers owner-side (can_*), grant
// (component_*_enabled), and deny (*_disabled) variants. Returns "" for
// non-catalog relations so audit consumers can filter cleanly.
// Spec: access-matrix-finish R6 AC 3 (regression-guarded via R6 AC 8).
func relationToActionClass(relation string) string {
	switch {
	case relation == "can_read",
		relation == "component_read_enabled",
		strings.HasSuffix(relation, "_read_disabled"):
		return "read"
	case relation == "can_configure",
		relation == "component_write_enabled",
		strings.HasSuffix(relation, "_write_disabled"):
		return "write"
	case relation == "can_execute",
		relation == "component_execute_enabled",
		strings.HasSuffix(relation, "_execute_disabled"):
		return "execute"
	}
	return ""
}

// FgaAuthzInterceptor is the single gRPC authorization interceptor that
// consults OpenFGA for every RPC's authorization decision.
//
// The 9-step flow (per design.md Component 1):
//  1. Extract identity from ctx; if nil AND not Unauthenticated → deny.
//  2. Lookup FullMethod in registry; if missing → deny (rpc_not_in_registry).
//  3. If Unauthenticated → pass through.
//  4. Derive user = "user:" + identity.Subject.
//  5. Derive object via registry.ObjectFrom or "tenant:" + TenantFromContext.
//  6. Call authorizer.Check(user, relation, object).
//  7. On error → Unavailable or PermissionDenied; emit deny audit event.
//  8. On deny → emit deny audit event; return PermissionDenied (generic msg).
//  9. On allow → emit allow audit event; pass through.
type FgaAuthzInterceptor struct {
	authorizer authz.Authorizer
	registry   *FgaRpcRegistry
	logger     *slog.Logger
	metrics    fgaMetricsRecorder
	tracer     oteltrace.Tracer
}

// NewFgaAuthzInterceptor constructs the interceptor. All parameters are required;
// a nil authorizer or registry will cause a panic at construction time so
// misconfiguration is caught at startup.
//
// The `m` parameter is typed as an interface rather than the concrete
// *observability.OTelMetricsRecorder to avoid an import cycle between the
// auth and observability packages. Callers pass the concrete type directly
// — it satisfies the interface structurally.
func NewFgaAuthzInterceptor(
	a authz.Authorizer,
	r *FgaRpcRegistry,
	l *slog.Logger,
	m fgaMetricsRecorder,
) *FgaAuthzInterceptor {
	if a == nil {
		panic("NewFgaAuthzInterceptor: authorizer must not be nil")
	}
	if r == nil {
		panic("NewFgaAuthzInterceptor: registry must not be nil")
	}
	if l == nil {
		l = slog.Default()
	}
	return &FgaAuthzInterceptor{
		authorizer: a,
		registry:   r,
		logger:     l,
		metrics:    m,
		tracer:     otel.Tracer(fgaAuthzTracerName),
	}
}

// Unary returns a grpc.UnaryServerInterceptor that enforces FGA authorization.
// Install after the auth interceptor (which populates Identity) and before handlers.
func (i *FgaAuthzInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, span := i.tracer.Start(ctx, fgaAuthzSpanName,
			oteltrace.WithSpanKind(oteltrace.SpanKindServer),
			oteltrace.WithAttributes(attribute.String("rpc.method", info.FullMethod)),
		)
		defer span.End()

		if err := i.checkInternal(ctx, req, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream returns a grpc.StreamServerInterceptor that enforces FGA authorization
// once at stream open. Auth is checked once, not per message.
func (i *FgaAuthzInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ss.Context()
		ctx, span := i.tracer.Start(ctx, fgaAuthzSpanName,
			oteltrace.WithSpanKind(oteltrace.SpanKindServer),
			oteltrace.WithAttributes(
				attribute.String("rpc.method", info.FullMethod),
				attribute.Bool("rpc.is_streaming", true),
			),
		)
		defer span.End()

		if err := i.checkInternal(ctx, nil, info.FullMethod); err != nil {
			return err
		}
		// Wrap stream to propagate enriched context.
		return handler(srv, &fgaWrappedStream{ServerStream: ss, ctx: ctx})
	}
}

// checkInternal runs the 9-step authorization flow and returns a gRPC status
// error on denial, or nil on allow.
func (i *FgaAuthzInterceptor) checkInternal(ctx context.Context, req any, fullMethod string) error {
	// Step 1: extract identity.
	identity, hasIdentity := GibsonIdentityFromContext(ctx)

	// Step 2: registry lookup.
	spec, found := i.registry.Lookup(fullMethod)
	if !found {
		i.logger.Error("fga_authz: rpc not in registry (default-deny)",
			"method", fullMethod,
		)
		i.incrementDecision(ctx, "deny", fullMethod)
		logAuditEvent(ctx, i.logger, &AuditEvent{
			EventType:          "authz_deny",
			Method:             fullMethod,
			Reason:             "rpc_not_in_registry",
			PermissionRequired: "rpc_not_in_registry: " + fullMethod,
			Success:            false,
		})
		return status.Errorf(codes.PermissionDenied, "authorization failed")
	}

	// Step 3: unauthenticated pass-through.
	if spec.Unauthenticated {
		return nil
	}

	// Step 1 (continued): identity required for authenticated RPCs.
	if !hasIdentity || identity == nil || identity.Subject == "" {
		i.logger.Warn("fga_authz: no identity for authenticated rpc",
			"method", fullMethod,
		)
		i.incrementDecision(ctx, "deny", fullMethod)
		logAuditEvent(ctx, i.logger, &AuditEvent{
			EventType:          "authz_deny",
			Method:             fullMethod,
			Reason:             "no_identity",
			PermissionRequired: spec.Description,
			FgaRelation:        spec.Relation,
			Success:            false,
		})
		return status.Errorf(codes.PermissionDenied, "authorization failed")
	}

	// Step 4: derive user.
	// Infrastructure SPIFFE IDs (platform/dashboard, platform/daemon) bypass FGA —
	// they are on the hardcoded allowlist in spiffeFGABypass. All other identities
	// (component SPIFFE IDs, API keys, Agent Auth, Better Auth) go through FGA.
	if spiffeFGABypass[identity.Subject] {
		return nil
	}
	user := "user:" + identity.Subject

	// Step 5: derive object.
	var object string
	var objErr error
	if spec.ObjectFrom != nil {
		object, objErr = spec.ObjectFrom(req, ctx)
	} else {
		object, objErr = tenantFromCtx()(req, ctx)
	}
	if objErr != nil {
		i.logger.Warn("fga_authz: failed to derive fga object",
			"method", fullMethod,
			"subject", identity.Subject,
			"error", objErr,
		)
		i.incrementDecision(ctx, "deny", fullMethod)
		logAuditEvent(ctx, i.logger, &AuditEvent{
			EventType:          "authz_deny",
			Method:             fullMethod,
			Subject:            identity.Subject,
			Reason:             "no_tenant",
			PermissionRequired: spec.Description,
			FgaRelation:        spec.Relation,
			Success:            false,
		})
		return status.Errorf(codes.PermissionDenied, "authorization failed")
	}

	// Step 6: call FGA Check (owner identity for agent-auth; direct for
	// everyone else).
	tenant := TenantFromContext(ctx)
	allowed, checkErr := i.authorizer.Check(ctx, user, spec.Relation, object)

	// Step 6b: when the caller is on the agent-auth path AND the RPC's
	// relation is a catalog-gated action (can_read / can_configure /
	// can_execute), run a second check against the component's per-action
	// grant. Both checks must pass for the RPC to proceed. component_scope
	// is required for any agent-auth caller; its absence is a hard deny.
	// Spec R2 AC 4/5.
	if identity.Issuer == agentAuthIssuer && checkErr == nil && allowed {
		componentScope := ComponentScopeFromContext(ctx)
		if componentScope == "" {
			i.logger.Warn("fga_authz: agent-auth caller missing component_scope",
				"method", fullMethod,
				"subject", identity.Subject,
			)
			i.incrementDecision(ctx, "deny", fullMethod)
			logAuditEvent(ctx, i.logger, &AuditEvent{
				EventType:          "authz_deny",
				Method:             fullMethod,
				Subject:            identity.Subject,
				TenantID:           tenant,
				Reason:             "component_scope_missing",
				PermissionRequired: spec.Description,
				FgaRelation:        spec.Relation,
				FgaObject:          object,
				ActionClass:        relationToActionClass(spec.Relation),
				ComponentScope:     "",
				Success:            false,
			})
			return status.Errorf(codes.PermissionDenied, "component_scope required")
		}
		if componentRelation, ok := catalogRelationToComponentGrant(spec.Relation); ok {
			var compAllowed bool
			compAllowed, checkErr = i.authorizer.Check(ctx, componentScope, componentRelation, object)
			if checkErr == nil && !compAllowed {
				i.logger.Info("fga_authz: component scope denied",
					"method", fullMethod,
					"subject", identity.Subject,
					"component_scope", componentScope,
					"component_relation", componentRelation,
					"object", object,
				)
				i.incrementDecision(ctx, "deny", fullMethod)
				logAuditEvent(ctx, i.logger, &AuditEvent{
					EventType:          "authz_deny",
					Method:             fullMethod,
					Subject:            identity.Subject,
					TenantID:           tenant,
					Reason:             "component_scope_deny",
					PermissionRequired: spec.Description,
					FgaRelation:        componentRelation,
					FgaObject:          object,
					ActionClass:        relationToActionClass(componentRelation),
					ComponentScope:     componentScope,
					Success:            false,
				})
				return status.Errorf(codes.PermissionDenied, "authorization failed")
			}
			// If compAllowed is true, proceed with `allowed == true`.
			// If checkErr is non-nil, let the shared error-handling path below
			// surface the FGA failure.
		}
	}

	// Step 7: error from FGA.
	if checkErr != nil {
		// Treat gRPC codes.Unavailable and codes.DeadlineExceeded from the
		// authorizer as infrastructure failures (same as authz.ErrFgaUnavailable).
		// This covers both the production FGA client (which wraps as
		// authz.ErrFgaUnavailable) and test stubs that return raw gRPC statuses.
		if st, ok := status.FromError(checkErr); ok &&
			(st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded) {
			checkErr = authz.ErrFgaUnavailable
		}
		if errors.Is(checkErr, authz.ErrFgaUnavailable) || errors.Is(checkErr, authz.ErrFgaTimeout) {
			i.logger.Error("fga_authz: fga service unavailable",
				"method", fullMethod,
				"subject", identity.Subject,
				"relation", spec.Relation,
				"object", object,
				"error", checkErr,
			)
			if i.metrics != nil {
				i.metrics.RecordFgaUnavailable(ctx, fullMethod)
			}
			logAuditEvent(ctx, i.logger, &AuditEvent{
				EventType:   "authz_deny",
				Method:      fullMethod,
				Subject:     identity.Subject,
				TenantID:    tenant,
				Reason:      "fga_unavailable",
				FgaRelation: spec.Relation,
				FgaObject:   object,
				Success:     false,
			})
			return status.Errorf(codes.Unavailable, "authorization service unavailable")
		}
		// Other FGA error — fail closed.
		i.logger.Error("fga_authz: fga check error",
			"method", fullMethod,
			"subject", identity.Subject,
			"relation", spec.Relation,
			"object", object,
			"error", checkErr,
		)
		i.incrementDecision(ctx, "deny", fullMethod)
		logAuditEvent(ctx, i.logger, &AuditEvent{
			EventType:   "authz_deny",
			Method:      fullMethod,
			Subject:     identity.Subject,
			TenantID:    tenant,
			Reason:      "fga_error",
			FgaRelation: spec.Relation,
			FgaObject:   object,
			Success:     false,
		})
		return status.Errorf(codes.PermissionDenied, "authorization failed")
	}

	// Step 8: explicit deny.
	if !allowed {
		i.logger.Info("fga_authz: access denied",
			"method", fullMethod,
			"subject", identity.Subject,
			"tenant", tenant,
			"relation", spec.Relation,
			"object", object,
		)
		i.incrementDecision(ctx, "deny", fullMethod)
		logAuditEvent(ctx, i.logger, &AuditEvent{
			EventType:          "authz_deny",
			Method:             fullMethod,
			Subject:            identity.Subject,
			TenantID:           tenant,
			Roles:              identity.Roles,
			Reason:             "fga_deny",
			PermissionRequired: spec.Description,
			FgaRelation:        spec.Relation,
			FgaObject:          object,
			ActionClass:        relationToActionClass(spec.Relation),
			ComponentScope:     ComponentScopeFromContext(ctx),
			Success:            false,
		})
		return status.Errorf(codes.PermissionDenied, "authorization failed")
	}

	// Step 9: allow.
	i.logger.Debug("fga_authz: access allowed",
		"method", fullMethod,
		"subject", identity.Subject,
		"tenant", tenant,
		"relation", spec.Relation,
		"object", object,
	)
	i.incrementDecision(ctx, "allow", fullMethod)
	logAuditEvent(ctx, i.logger, &AuditEvent{
		EventType:          "authz_allow",
		Method:             fullMethod,
		Subject:            identity.Subject,
		TenantID:           tenant,
		Roles:              identity.Roles,
		PermissionRequired: spec.Description,
		FgaRelation:        spec.Relation,
		FgaObject:          object,
		Success:            true,
	})
	return nil
}

// incrementDecision records an authz decision metric. Safe with nil metrics.
func (i *FgaAuthzInterceptor) incrementDecision(ctx context.Context, decision, method string) {
	if i.metrics != nil {
		i.metrics.RecordAuthzDecision(ctx, decision, method, "")
	}
}

// fgaWrappedStream wraps a ServerStream to carry an enriched context.
type fgaWrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fgaWrappedStream) Context() context.Context { return s.ctx }
