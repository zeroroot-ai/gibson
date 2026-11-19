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
//	skill:<name>           → Check(agent, can_load, agent_skill:<tenant>/<name>)
//	                         or Check(mission:<id>, can_load, the same object)
//
// An Agent Skill has no default grant. The user of the run holds no right to
// it. A tenant admin grants it to an agent or to a mission, so the check reads
// Caller.Agent and Caller.Mission and never Caller.Subject.
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
	if id.Source == toolid.SourceSkill {
		return a.canLoadSkill(ctx, caller, id)
	}
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

// agentPrincipalPrefix is the FGA type of an agent identity.
const agentPrincipalPrefix = "agent_principal:"

// canLoadSkill answers "may this caller load this Agent Skill". The caller may
// load it when its agent has a grant, or when its mission has a grant. The tenant
// of the object is the tenant of the caller, so a grant in one tenant says
// nothing about another. It is fail-closed: no tenant, or no agent and no
// mission, is an error.
func (a *FGAAuthorizer) canLoadSkill(ctx context.Context, caller Caller, id toolid.ID) (bool, error) {
	object, err := authz.AgentSkillObject(caller.Tenant, id.Tool)
	if err != nil {
		return false, fmt.Errorf("catalog: authz check for %q: %w", id.Canonical(), err)
	}
	var subjects []string
	if strings.HasPrefix(caller.Agent, agentPrincipalPrefix) {
		subjects = append(subjects, caller.Agent)
	}
	if caller.Mission != "" {
		subjects = append(subjects, "mission:"+caller.Mission)
	}
	if len(subjects) == 0 {
		return false, fmt.Errorf("catalog: authz check for %q: the caller has no agent principal and no mission",
			id.Canonical())
	}
	for _, subject := range subjects {
		ok, err := a.fga.Check(ctx, subject, "can_load", object)
		if err != nil {
			return false, fmt.Errorf("catalog: authz check for %q: %w", id.Canonical(), err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
