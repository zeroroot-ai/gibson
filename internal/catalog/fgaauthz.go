package catalog

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/toolid"
)

// Checker is the narrow FGA check surface the authorizer needs. It is satisfied
// by the daemon's FGA authorizer (Check(ctx, user, relation, object)).
type Checker interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
}

// FGAAuthorizer implements Authorizer by mapping a tool id to the FGA
// (relation, object) that gates its use, then checking it against an FGA Checker.
//
// Per the gibson#694 decision, the mapping is by source:
//
//	mcp:<connector>:<tool>  → can_invoke on plugin:<tenant>:<connector>
//
// This is exactly the gate PluginInvoke enforces (object_deriver
// tenant_and_field('PluginName') → plugin:<tenant>:<connector>), so a tool that
// passes the SearchTools filter is one the caller can actually invoke. The object
// is tenant-qualified, so there is no cross-tenant exposure.
//
// Native/component tools are deferred until the inconsistent component: object
// space is reconciled (gibson#700); for now FGAAuthorizer fails closed on them.
type FGAAuthorizer struct {
	checker Checker
}

// NewFGAAuthorizer constructs an FGAAuthorizer over an FGA Checker.
func NewFGAAuthorizer(checker Checker) *FGAAuthorizer {
	return &FGAAuthorizer{checker: checker}
}

// Compile-time assertion that FGAAuthorizer satisfies Authorizer.
var _ Authorizer = (*FGAAuthorizer)(nil)

// CanExecute reports whether the caller may use the tool, by checking the
// source-appropriate FGA relation/object. Unsupported or under-specified inputs
// fail closed (deny, no error).
func (a *FGAAuthorizer) CanExecute(ctx context.Context, caller Caller, id toolid.ID) (bool, error) {
	user, relation, object, ok := fgaRefFor(caller, id)
	if !ok {
		return false, nil
	}
	return a.checker.Check(ctx, user, relation, object)
}

// fgaRefFor maps (caller, id) to the FGA (user, relation, object) tuple to check.
// ok is false — fail closed — when the identity is incomplete or the source is
// not yet supported (native, pending gibson#700).
func fgaRefFor(caller Caller, id toolid.ID) (user, relation, object string, ok bool) {
	if caller.Subject == "" || caller.Tenant == "" {
		return "", "", "", false
	}
	switch id.Source {
	case toolid.SourceMCP:
		if id.Connector == "" {
			return "", "", "", false
		}
		// An MCP connector is a plugin; the invocation gate is can_invoke on the
		// tenant-qualified plugin object (matches PluginInvoke + plugin_grants).
		return caller.Subject, "can_invoke", "plugin:" + caller.Tenant + ":" + id.Connector, true
	default:
		// Native/component tools: deferred until the component: object space is
		// reconciled (gibson#700).
		return "", "", "", false
	}
}
