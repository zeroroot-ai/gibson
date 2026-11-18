// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/platform/agentskillstore"
	"github.com/zeroroot-ai/sdk/auth"
)

// AgentSkillStoreSource returns the Agent Skill store of this daemon, or nil
// when the data plane is not ready. It is read for each call because the
// per-tenant data pool is built after the callback options are assembled.
type AgentSkillStoreSource func() agentskillstore.Store

// WithAgentSkillStore wires the source of the Agent Skill store. A daemon with
// none offers no Agent Skill. The catalog search then returns tools only.
func WithAgentSkillStore(src AgentSkillStoreSource) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.agentSkills = src
	}
}

// agentSkillStore returns the store, or nil when none is wired or ready.
func (s *HarnessCallbackService) agentSkillStore() agentskillstore.Store {
	if s.agentSkills == nil {
		return nil
	}
	return s.agentSkills()
}

// toolLister returns the lister of the catalog: the tools and, when the store
// is ready, the Agent Skills of the tenant.
func (s *HarnessCallbackService) toolLister(tools catalog.ToolLister) catalog.ToolLister {
	if store := s.agentSkillStore(); store != nil {
		return catalog.CombineListers(tools, agentskillstore.ToolLister{Store: store})
	}
	return tools
}

// catalogCaller builds the caller of a catalog call from the run state and the
// identity of the request. Agent is set only when the identity is an agent
// principal, because an Agent Skill grant names an agent or a mission and never
// the user of the run.
func catalogCaller(ctx context.Context, state *RunAuthzState) catalog.Caller {
	caller := catalog.Caller{Subject: "user:" + state.UserID, Tenant: state.TenantID, Mission: state.MissionID}
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		if subject := callbackFGAUser(id.Subject); strings.HasPrefix(subject, "agent_principal:") {
			caller.Agent = subject
		}
	}
	return caller
}
