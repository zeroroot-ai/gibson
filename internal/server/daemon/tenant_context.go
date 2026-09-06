// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// tenant_context.go owns the daemon package's single tenant-resolution helper.
//
// It lives in its own file (rather than beside the mission manager, where its
// predecessor sat) because it is the tenant boundary for every tenant-scoped
// daemon operation — mission lifecycle, mission-definition CRUD, mission
// history, and the harness mission adapter all go through it. One file, one
// rule, one grep.

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"
)

// errNoTenantInContext is the fail-closed refusal tenantFromCtx returns when
// the caller's context carries no tenant.
//
// FailedPrecondition mirrors DaemonServer.GetMyPermissions' refusal shape: the
// daemon is telling the caller the request cannot be served as presented. It
// deliberately does not distinguish "no identity at all" from "identity with no
// tenant" — both are the same unservable request from the caller's side, and
// splitting them would leak which half of the auth chain dropped the tenant.
var errNoTenantInContext = status.Error(
	codes.FailedPrecondition,
	"no tenant in context: this operation is tenant-scoped and cannot be served without an authenticated tenant",
)

// tenantFromCtx resolves the tenant a tenant-scoped daemon operation runs
// under. An absent tenant is REFUSED. It is never defaulted, and in particular
// it is never widened to auth.SystemTenant.
//
// This replaces tenantFromCtxOrSystem (gibson#1232), which returned
// auth.SystemTenant whenever auth.TenantFromContext reported no tenant. That
// default inverted the failure mode: a request that had somehow lost its tenant
// — a gap in the identity chain, a handler reached off the interceptor path, a
// context detached from its identity — did not fail, it silently acquired the
// single most privileged tenant in the system and then ran the caller's
// operation under it. The pool selects the data plane from that TenantID, so
// the escalation was not advisory; it chose which store the operation read and
// wrote. auth.TenantFromContext' own doc comment states the contract this
// function now keeps: "The caller MUST treat false as fail-closed — there is no
// defaulting to SystemTenant or any other fallback."
//
// No caller in this package is a genuine system-tenant caller: every one of the
// call sites is a request-scoped gRPC handler reached only through the strict
// sdk/auth interceptor (none of the affected methods is registry-classified
// Unauthenticated or Self, so none can arrive via the loose-mode path), plus
// the harness mission adapter, whose contexts descend from newMissionContext
// and therefore already carry the run's tenant explicitly.
//
// Daemon-internal Go code that genuinely needs the reserved system tenant must
// say so at its own call site by stamping the context:
//
//	ctx = auth.ContextWithTenant(ctx, auth.SystemTenant)
//
// That keeps the escalation opt-in and greppable at the point where the
// decision is actually made — auth.SystemTenant is documented by the SDK as
// "the single audit-grep handle" for exactly these paths. A resolver-level
// default is the opposite: it hides the decision from every call site at once.
// A wrapper helper here would only add an alias to grep for, so there
// deliberately is not one.
func tenantFromCtx(ctx context.Context) (auth.TenantID, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return auth.TenantID{}, errNoTenantInContext
	}
	return tenant, nil
}
