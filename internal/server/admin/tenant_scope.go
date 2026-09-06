// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — tenant_scope.go
//
// The single place this package resolves the tenant an admin RPC operates on.
//
// ext-authz authorizes every RPC in this package against an object derived
// from the CALLER's own identity (`object_deriver: tenant_from_identity` in the
// authz registry). No deriver reads a request body, so a tenant_id arriving on
// the wire is authorized by nothing: it must never select the tenant a handler
// acts on. membership.proto already documents the field as "must match the
// authenticated caller's tenant"; requireCallerTenant is what makes that
// documented contract true.
//
// Handlers therefore call requireCallerTenant and use only its return value.
// Where an RPC genuinely needs to act on a different tenant, it must gate on an
// explicit admin / platform_operator re-check (the shape
// DaemonServer.requireTenantAdmin implements), not on an unchecked body field.
package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"
)

// tenantScopedRequest is satisfied by every request message in this package
// that carries a tenant_id field.
type tenantScopedRequest interface {
	GetTenantId() string
}

// requireCallerTenant returns the authenticated caller's tenant, and rejects a
// request whose tenant_id names anyone else.
//
// The returned value is always the context tenant — the wire field can never
// widen the scope, only fail the call. An empty tenant_id is accepted (the
// field is optional); a populated one must match, so a client that sends a
// tenant it does not hold gets a loud PermissionDenied rather than a silently
// re-scoped write. The comparison tolerates an already-prefixed
// "tenant:<slug>" value for the same reason tenantRefFromID does.
//
// gibsoncheck:allow tenant-from-request — this function IS the guard. It is
// the only place in the package that reads the wire tenant, and it uses the
// value solely as the right-hand side of an equality check against the
// caller's context tenant; the value it returns is always the context tenant.
func requireCallerTenant(ctx context.Context, req tenantScopedRequest) (string, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return "", status.Error(codes.PermissionDenied, "no tenant in context")
	}
	callerTenant := tenant.String()
	if wire := req.GetTenantId(); wire != "" && stripFGATypePrefix(wire, "tenant") != callerTenant {
		return "", status.Error(codes.PermissionDenied,
			"tenant_id does not match the authenticated caller's tenant")
	}
	return callerTenant, nil
}
