package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/casbin/casbin/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SetAuthzSpanAttrsFunc sets gibson.authz.* attributes on the active span.
// Injected at construction from observability.SetAuthzAttributes to avoid
// an import cycle (observability already imports auth for tenant context).
type SetAuthzSpanAttrsFunc func(ctx context.Context, method, subject, tenant, permission string, allowed bool, reason string)

// RecordAuthzMetricFunc increments the authz decisions counter.
// Injected at construction from observability.OTelMetricsRecorder.RecordAuthzDecision
// for the same import-cycle reason.
type RecordAuthzMetricFunc func(ctx context.Context, decision, method, permission string)

// RPCAuthzInterceptor enforces per-RPC authorization by looking the method
// up in the SchemaRegistry loaded from permissions.yaml at startup and
// calling Casbin with the caller's identity + tenant context + required
// permission. It is the single enforcement point for every gRPC method in
// the daemon.
//
// This interceptor sits in the chain AFTER the existing auth interceptors
// (which populate Identity in context) and BEFORE the handlers (which no
// longer contain any hand-rolled role checks after the
// declarative-rbac-framework refactor).
//
// Contract:
//
//   - Unmapped RPC → codes.PermissionDenied, audit reason "rpc_not_in_schema"
//     (default-deny: a developer who adds an RPC without updating
//     permissions.yaml will see their call rejected, and the CI coverage
//     test catches it pre-merge).
//   - RPC with unauthenticated=true → interceptor skips authorization and
//     lets the handler run (used for token-based flows like
//     AcceptInvitation where the token itself is the proof of authorization).
//   - No identity in context on an authenticated RPC → codes.PermissionDenied
//     with reason "no_identity" (this indicates a bug in the upstream auth
//     interceptor chain; we fail closed rather than panicking).
//   - RPC with required_permissions → interceptor iterates each permission
//     and calls casbin.Enforcer.Enforce. Any denial fails the whole call.
//   - RPC with empty required_permissions → any authenticated caller passes
//     (used for GetAuthSchema bootstrap).
//
// Every decision (allow or deny) emits:
//   - A structured slog audit event via logAuditEvent (routed to Loki)
//   - OTel span attributes via observability.SetAuthzAttributes (routed to
//     Langfuse and Jaeger)
//   - A Prometheus counter increment via RecordAuthzDecision (scraped to
//     Grafana)
//
// The gRPC error returned to the caller never leaks internal reason strings,
// permission names, or role lists. All detailed reasons go to audit/OTel/
// metrics only.
type RPCAuthzInterceptor struct {
	registry *SchemaRegistry
	enforcer *casbin.Enforcer
	logger   *slog.Logger
	// Observability hooks are injected as function values rather than a
	// concrete observability.OTelMetricsRecorder pointer to avoid an
	// import cycle with the observability package.
	setSpanAttrs SetAuthzSpanAttrsFunc
	recordMetric RecordAuthzMetricFunc
}

// NewRPCAuthzInterceptor constructs the interceptor with its dependencies.
// Both registry and enforcer must be non-nil or NewRPCAuthzInterceptor
// returns an error — a misconfigured daemon must not start with a half-
// initialized authz interceptor. The observability hooks may be nil in
// tests; production wiring passes observability.SetAuthzAttributes and
// metricsRecorder.RecordAuthzDecision.
func NewRPCAuthzInterceptor(
	registry *SchemaRegistry,
	enforcer *casbin.Enforcer,
	logger *slog.Logger,
	setSpanAttrs SetAuthzSpanAttrsFunc,
	recordMetric RecordAuthzMetricFunc,
) (*RPCAuthzInterceptor, error) {
	if registry == nil {
		return nil, fmt.Errorf("rpc_authz_interceptor: registry is required")
	}
	if enforcer == nil {
		return nil, fmt.Errorf("rpc_authz_interceptor: enforcer is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RPCAuthzInterceptor{
		registry:     registry,
		enforcer:     enforcer,
		logger:       logger,
		setSpanAttrs: setSpanAttrs, // may be nil
		recordMetric: recordMetric, // may be nil
	}, nil
}

// Unary returns the grpc.UnaryServerInterceptor to register on the server.
// Install AFTER UnaryAuthInterceptor so Identity is already in context.
func (i *RPCAuthzInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := i.authorize(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream returns the grpc.StreamServerInterceptor to register on the server.
// Install AFTER StreamAuthInterceptor so Identity is already in context.
func (i *RPCAuthzInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := i.authorize(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// genericAuthzError is the public-facing gRPC error returned to callers on
// any authz denial. Never varies by reason — detailed reasons go to server
// logs and audit events only, so the wire response cannot be used to
// enumerate the platform's permission surface.
func genericAuthzError() error {
	return status.Error(codes.PermissionDenied, "authorization failed")
}

// authorize is the core enforcement function shared by the unary and
// stream interceptors. Returns nil on allow, a gRPC status error on deny.
//
// Every code path emits exactly one audit event, one OTel attribute set,
// and one counter increment so observability is consistent regardless of
// the decision branch taken.
func (i *RPCAuthzInterceptor) authorize(ctx context.Context, method string) error {
	req := i.registry.GetRPCRequirement(method)
	if req == nil {
		// Default-deny: the RPC is not in permissions.yaml. A developer
		// added an RPC without updating the YAML, or (less likely) the
		// proto coverage CI test missed it. Fail closed.
		i.recordDecision(ctx, method, "", "", nil, false, "rpc_not_in_schema")
		return genericAuthzError()
	}

	// Unauthenticated RPCs (e.g. AcceptInvitation) skip authz entirely.
	// The handler validates the self-contained token.
	if req.Unauthenticated {
		i.recordDecision(ctx, method, "", "*", nil, true, "unauthenticated_rpc")
		return nil
	}

	identity, ok := GibsonIdentityFromContext(ctx)
	if !ok || identity == nil {
		// The existing auth interceptor chain should have populated this
		// before we reach the authz interceptor. Reaching here indicates
		// a misconfiguration in the interceptor order or a bypass bug.
		i.recordDecision(ctx, method, "", "", nil, false, "no_identity")
		return genericAuthzError()
	}

	// Determine the tenant domain to pass Casbin. Tenant-scoped RPCs use
	// the caller's tenant context; cross-tenant RPCs use "*".
	domain := "*"
	if req.TenantScoped {
		domain = TenantFromContext(ctx)
		if domain == "" {
			i.recordDecision(ctx, method, identity.Subject, "", identity.Roles, false, "tenant_missing_for_scoped_rpc")
			return genericAuthzError()
		}
	}

	// Resolve the caller's effective permissions directly from the YAML
	// role closure. This is the single source of truth for "what can this
	// caller do" and is used for both the audit event payload AND the
	// enforcement check below.
	//
	// We deliberately do NOT call casbin.Enforce(subject, domain, obj, act)
	// here, even though the enforcer is still available on `i.enforcer`
	// for future per-tenant use cases. The reason: casbin's matcher relies
	// on a `g` (grouping) rule linking the request subject UUID to a role
	// name, and that grouping rule is ONLY populated by the tenant
	// membership store (internal/membership/store.go) for users who are
	// members of a specific tenant. Cross-tenant callers — OIDC tokens
	// carrying a realm role (provisioner, platform-operator), K8s SA
	// tokens carrying a component role (tool-executor, agent-executor,
	// plugin-executor), and API keys carrying a default role (admin,
	// platform-operator) — have their Roles populated by the respective
	// auth validators BEFORE the authz interceptor runs, but those
	// validators never call enforcer.AddGroupingPolicy. Asking casbin
	// about those subjects therefore always returns deny, which is why
	// every cross-tenant RPC (ProvisionTenant for signup, PollWork /
	// Heartbeat / RegisterComponent for component workers, every
	// platform-operator admin call) was failing with
	// "missing_permission: X" even though the registry closure on the
	// same identity clearly contains X.
	//
	// Since identity.Roles is already populated by the trusted auth
	// interceptors (OIDC JWT validator, K8s TokenReview, HMAC-verified
	// API key) before this interceptor runs, and since tenant-scoped
	// auth uses the role that the membership store resolved for the
	// *active* tenant (so "alice is admin in tenant-a but not tenant-b"
	// is honoured at membership-store lookup time, not at enforce
	// time), the registry closure is both necessary and sufficient for
	// the per-RPC permission decision made here.
	grantedSet := i.registry.ResolvePermissions(identity.Roles)
	granted := make([]string, 0, len(grantedSet))
	for p := range grantedSet {
		granted = append(granted, p)
	}

	// Empty required_permissions means "any authenticated caller is
	// sufficient" — used exclusively for GetAuthSchema. We still emit a
	// full audit event so operators can see the access.
	if len(req.RequiredPermissions) == 0 {
		i.recordDecision(ctx, method, identity.Subject, domain, identity.Roles, true, "any_authenticated", withGranted(granted))
		return nil
	}

	// Enforce each required permission against the closure. ANY failure denies.
	for _, permName := range req.RequiredPermissions {
		if _, ok := i.registry.Permissions[permName]; !ok {
			// Should be impossible — the loader validates this at startup —
			// but belt-and-suspenders deny if it happens.
			i.recordDecision(ctx, method, identity.Subject, domain, identity.Roles, false,
				fmt.Sprintf("internal: permission %q not in registry", permName), withGranted(granted), withPermission(permName))
			return genericAuthzError()
		}
		if _, ok := grantedSet[permName]; !ok {
			reason := fmt.Sprintf("missing_permission: %s (caller_roles=[%s])", permName, strings.Join(identity.Roles, ","))
			i.recordDecision(ctx, method, identity.Subject, domain, identity.Roles, false, reason,
				withGranted(granted), withPermission(permName))
			return genericAuthzError()
		}
	}

	// All required permissions satisfied. Use the first required permission
	// as the "PermissionRequired" audit field (for multi-perm RPCs, the
	// allow event tags the first; the full list is in PermissionsGranted).
	firstPerm := req.RequiredPermissions[0]
	i.recordDecision(ctx, method, identity.Subject, domain, identity.Roles, true, "",
		withGranted(granted), withPermission(firstPerm))
	return nil
}

// decisionOption configures optional fields on the audit event record emitted
// for a single authorization decision. Keeps the recordDecision signature
// stable while letting callers set permission / granted when applicable.
type decisionOption func(*decisionState)

type decisionState struct {
	permission string
	granted    []string
}

func withPermission(p string) decisionOption { return func(d *decisionState) { d.permission = p } }
func withGranted(g []string) decisionOption  { return func(d *decisionState) { d.granted = g } }

// recordDecision emits the audit event, OTel attributes, and Prometheus
// counter for a single authorization decision. This is the one and only
// place the interceptor writes observability signals, so the three
// backends stay consistent even when code paths branch.
func (i *RPCAuthzInterceptor) recordDecision(
	ctx context.Context,
	method, subject, tenant string,
	roles []string,
	allowed bool,
	reason string,
	opts ...decisionOption,
) {
	var s decisionState
	for _, o := range opts {
		o(&s)
	}

	// 1. Audit event via existing logAuditEvent pipeline → Loki → Grafana.
	eventType := "authz_allow"
	if !allowed {
		eventType = "authz_deny"
	}
	logAuditEvent(ctx, i.logger, &AuditEvent{
		EventType:          eventType,
		Method:             method,
		Subject:            subject,
		TenantID:           tenant,
		Roles:              roles,
		Reason:             reason,
		Success:            allowed,
		PermissionRequired: s.permission,
		PermissionsGranted: s.granted,
	})

	// 2. OTel span attributes → Langfuse/Jaeger trace.
	if i.setSpanAttrs != nil {
		i.setSpanAttrs(ctx, method, subject, tenant, s.permission, allowed, reason)
	}

	// 3. Prometheus counter → existing scrape → Grafana metrics panels.
	if i.recordMetric != nil {
		decision := "allow"
		if !allowed {
			decision = "deny"
		}
		// For unmapped RPCs the permission is empty; label it "rpc_not_in_schema"
		// so Grafana queries can slice by the default-deny case without a
		// separate metric.
		metricPerm := s.permission
		if metricPerm == "" && reason == "rpc_not_in_schema" {
			metricPerm = "rpc_not_in_schema"
		}
		i.recordMetric(ctx, decision, method, metricPerm)
	}
}
