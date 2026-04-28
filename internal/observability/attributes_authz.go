package observability

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Authorization span attributes.
//
// Set by the RPC authz interceptor (internal/auth/rpc_authz_interceptor.go)
// on the active gRPC request span, making every authorization decision
// visible in Langfuse and Jaeger alongside every other span attribute,
// with no configuration changes required.
//
// Added by the declarative-rbac-framework spec (Requirement 9.4).
const (
	// GibsonAuthzMethod is the fully-qualified gRPC method path evaluated.
	// Example: "/gibson.tenant.v1.TenantAdminService/CreateAgentIdentity".
	GibsonAuthzMethod = "gibson.authz.method"

	// GibsonAuthzSubject is the authenticated identity's Subject field.
	GibsonAuthzSubject = "gibson.authz.subject"

	// GibsonAuthzTenant is the tenant domain used for enforcement.
	// "*" for cross-tenant RPCs, the caller's tenant for tenant-scoped RPCs.
	GibsonAuthzTenant = "gibson.authz.tenant"

	// GibsonAuthzPermissionRequired is the permission name the interceptor
	// evaluated, e.g. "tenants:provision". For RPCs that require multiple
	// permissions, this holds the first one that passed or the one that
	// failed (on deny).
	GibsonAuthzPermissionRequired = "gibson.authz.permission_required"

	// GibsonAuthzAllowed is a boolean: true if the RPC was permitted, false
	// if denied. Set on every request.
	GibsonAuthzAllowed = "gibson.authz.allowed"

	// GibsonAuthzReason carries the deny reason, e.g.
	// "missing_permission: tenants:provision" or "rpc_not_in_schema".
	// Set only when GibsonAuthzAllowed is false.
	GibsonAuthzReason = "gibson.authz.reason"
)

// SetAuthzAttributes sets Gibson-canonical authz attributes on the active
// span for a gRPC request. Attribute names follow the gibson.authz.*
// namespace so Langfuse and Jaeger can filter on them.
//
// Called from the RPC authz interceptor after the allow/deny decision is
// made, BEFORE the handler runs (for allow) or before the error is returned
// (for deny). If no span is active on ctx, this is a no-op.
//
// Parameters:
//
//	ctx        - gRPC request context (the interceptor's ctx parameter)
//	method     - fully-qualified gRPC method path from info.FullMethod
//	subject    - Identity.Subject from the authenticated caller (empty for
//	             unauthenticated RPCs)
//	tenant     - the tenant scope of the authz check ("*" for cross-tenant)
//	permission - the permission evaluated (empty when no permissions are
//	             required, e.g. for GetAuthSchema)
//	allowed    - the final decision: true for authz_allow, false for authz_deny
//	reason     - the deny reason; ignored when allowed is true
func SetAuthzAttributes(
	ctx context.Context,
	method, subject, tenant, permission string,
	allowed bool,
	reason string,
) {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		// No active span on this request — nothing to decorate. The audit
		// event (via logAuditEvent) still captures the decision.
		return
	}

	attrs := make([]attribute.KeyValue, 0, 6)
	if method != "" {
		attrs = append(attrs, attribute.String(GibsonAuthzMethod, method))
	}
	if subject != "" {
		attrs = append(attrs, attribute.String(GibsonAuthzSubject, subject))
	}
	if tenant != "" {
		attrs = append(attrs, attribute.String(GibsonAuthzTenant, tenant))
	}
	if permission != "" {
		attrs = append(attrs, attribute.String(GibsonAuthzPermissionRequired, permission))
	}
	attrs = append(attrs, attribute.Bool(GibsonAuthzAllowed, allowed))
	if !allowed && reason != "" {
		attrs = append(attrs, attribute.String(GibsonAuthzReason, reason))
	}

	span.SetAttributes(attrs...)
}
