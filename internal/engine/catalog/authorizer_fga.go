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
// relation) mapping (gibson#694):
//
//	mcp:<connector>:<tool> → Check(subject, can_invoke,  plugin:<tenant>:<connector>)
//	native:<tool>          → Check(subject, can_execute, component:<tool>)
//
// MCP tools route through the daemon's PluginInvoke path, so the filter runs
// the same check that gates the invocation: can_invoke on the
// tenant-qualified plugin object the tenant-operator seeds at enrollment.
// Native primitives check can_execute on the tenant-less component object;
// there the model's in_tenant_catalog gate plus the caller's tenant-scoped
// membership provide isolation.
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
		if caller.Tenant == "" {
			return false, fmt.Errorf("catalog: authz check for %q: mcp tools require a tenant-scoped caller", id.Canonical())
		}
		return a.fga.Check(ctx, caller.Subject, "can_invoke", authz.PluginObject(caller.Tenant, id.Connector))
	case toolid.SourceNative:
		return a.fga.Check(ctx, caller.Subject, "can_execute", authz.ComponentObject(id.Tool))
	default:
		return false, fmt.Errorf("catalog: authz check for %q: unknown tool source %q", id.Canonical(), id.Source)
	}
}
