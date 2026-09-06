// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package catalog

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
)

// Checker is the narrow FGA surface the production Authorizer needs. It is
// satisfied by authz.Authorizer; tests supply a fake.
type Checker interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
}

// FGAAuthorizer is the production catalog [Authorizer]: it answers "may this
// caller execute this tool" with the standardized (tool source → FGA object,
// relation) mapping (gibson#694, ADR-0067):
//
//	mcp:<connector>:<tool> → Check(subject, can_execute, component:connector/<connector>)
//	native:<tool>          → Check(subject, can_execute, component:<tool>)
//
// Both sources check can_execute on a component object — connectors are the
// fourth component kind, and their execute gate is per connector, covering
// every tool the connector exposes. The old borrow of the `plugin` object
// (can_invoke on plugin:<tenant>/<connector>) is retired: the `plugin` FGA
// type serves true plugin invocation only. Tenant isolation comes from the
// model's in_tenant_catalog gate (the tenant-operator seeds owner +
// tenant_enabled per enabling tenant) plus the caller's tenant-scoped
// membership — identical for both sources.
//
// Caller.Subject must be a typed FGA reference ("user:<uuid>",
// "agent_principal:<id>", …) — exactly the subject the corresponding
// invocation-time check would use, so search can never surface a tool whose
// invocation would be denied. All ambiguity is resolved fail-closed: missing
// subject, missing tenant (for MCP), or an unknown source is an error, never
// a silent allow.
type FGAAuthorizer struct {
	fga Checker
}

// NewFGAAuthorizer constructs the production Authorizer over an FGA checker.
func NewFGAAuthorizer(fga Checker) *FGAAuthorizer {
	if fga == nil {
		panic("catalog: NewFGAAuthorizer: fga checker must not be nil")
	}
	return &FGAAuthorizer{fga: fga}
}

var _ Authorizer = (*FGAAuthorizer)(nil)

// CanExecute implements [Authorizer].
func (a *FGAAuthorizer) CanExecute(ctx context.Context, caller Caller, id toolid.ID) (bool, error) {
	if caller.Subject == "" {
		return false, fmt.Errorf("catalog: authz check for %q: caller subject is required", id.Canonical())
	}
	switch id.Source {
	case toolid.SourceMCP:
		ok, err := a.fga.Check(ctx, caller.Subject, "can_execute", authz.ConnectorComponentObject(id.Connector))
		if err != nil {
			return false, fmt.Errorf("catalog: authz check for %q: %w", id.Canonical(), err)
		}
		return ok, nil
	case toolid.SourceNative:
		ok, err := a.fga.Check(ctx, caller.Subject, "can_execute", authz.ComponentObject(authz.KindTool, id.Tool))
		if err != nil {
			return false, fmt.Errorf("catalog: authz check for %q: %w", id.Canonical(), err)
		}
		return ok, nil
	default:
		return false, fmt.Errorf("catalog: authz check for %q: unknown tool source %q", id.Canonical(), id.Source)
	}
}
