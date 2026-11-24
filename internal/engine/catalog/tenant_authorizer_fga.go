// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package catalog

import (
	"context"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// RelationTenantCanExecute is the relation of the component type that asks
// "may the tenant run this component for itself". The rule is in the model
// (internal/platform/authz/model.fga), and this file only asks it.
const RelationTenantCanExecute = "tenant_can_execute"

// TenantSetSubject is the subject that names a call which the daemon makes for a
// tenant with no person or agent behind it. It is the actor of the audit record
// of such a call. It is not an FGA user: a userset cannot ask can_execute.
func TenantSetSubject(tenant string) string { return "tenant:" + tenant + "#member" }

// TenantAuthorizer is the [Authorizer] of a call that the daemon makes for a
// tenant: the read of a scan, the revert of a fix, a bank member. It asks the
// plain tenant for tenant_can_execute on the connector component. It never
// answers for a person or an agent, and it refuses a caller that is not the
// tenant set of its own tenant. A source other than a connector tool is
// delegated to base, which holds the rule of an Agent Skill.
type TenantAuthorizer struct {
	fga  Checker
	base Authorizer
}

// NewTenantAuthorizer builds the authorizer over an FGA checker and the base
// authorizer of every other caller.
func NewTenantAuthorizer(fga Checker, base Authorizer) *TenantAuthorizer {
	if fga == nil || base == nil {
		panic("catalog: NewTenantAuthorizer: fga checker and base authorizer must not be nil")
	}
	return &TenantAuthorizer{fga: fga, base: base}
}

var _ Authorizer = (*TenantAuthorizer)(nil)

// CanExecute implements [Authorizer].
func (a *TenantAuthorizer) CanExecute(ctx context.Context, caller Caller, id toolid.ID) (bool, error) {
	if id.Source != toolid.SourceMCP {
		return a.base.CanExecute(ctx, caller, id)
	}
	if caller.Tenant == "" || strings.ContainsAny(caller.Tenant, ":# \t\n") || caller.Subject != TenantSetSubject(caller.Tenant) {
		return false, fmt.Errorf("catalog: authz check for %q: the caller is not the tenant set of tenant %q", id.Canonical(), caller.Tenant)
	}
	ok, err := a.fga.Check(ctx, "tenant:"+caller.Tenant, RelationTenantCanExecute, authz.ConnectorComponentObject(id.Connector))
	if err != nil {
		return false, fmt.Errorf("catalog: authz check for %q: %w", id.Canonical(), err)
	}
	return ok, nil
}
