// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"strings"
	"time"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
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

// SkillLoadRecord is one successful load of an Agent Skill by a mission agent.
type SkillLoadRecord struct {
	MissionID    string
	MissionRunID string
	RunID        string
	Agent        string
	Name         string
	Digest       string
	// File is the reference file of the load. It is empty for the body.
	File               string
	RecordedAtUnixNano int64
}

// ErrNoSkillLoadSink is the answer of a daemon that wired no sink for the loads
// of Agent Skills. A load then fails, because no load goes without its record.
var ErrNoSkillLoadSink = errors.New("harness: this daemon records no Agent Skill loads")

// SkillLoadSink receives each successful load. The daemon wires it to the
// Timeline of the tenant. When it returns an error, the load is refused and the
// agent gets nothing.
type SkillLoadSink func(ctx context.Context, tenant string, load SkillLoadRecord) error

// WithSkillLoadSink sets the sink of the loads of Agent Skills.
func WithSkillLoadSink(sink SkillLoadSink) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.skillLoadSink = sink
	}
}

// noSkillLoadSink is the default sink. It refuses each load.
func noSkillLoadSink(context.Context, string, SkillLoadRecord) error { return ErrNoSkillLoadSink }

// noAgentSkillStore is the default source of the store. A daemon with no data
// plane serves no Agent Skill.
func noAgentSkillStore() agentskillstore.Store { return nil }

// skillLoadHook returns the function that metatool calls after a successful
// load. It stamps the time here, so the Timeline event carries it.
func (s *HarnessCallbackService) skillLoadHook(info *harnesspb.ContextInfo) func(context.Context, metatool.SkillLoad) error {
	return func(ctx context.Context, l metatool.SkillLoad) error {
		return s.skillLoadSink(ctx, l.Tenant, SkillLoadRecord{
			MissionID: l.MissionID, MissionRunID: info.GetMissionRunId(), RunID: l.RunID, Agent: l.Agent,
			Name: l.Name, Digest: l.Digest, File: l.File, RecordedAtUnixNano: time.Now().UnixNano(),
		})
	}
}

// agentSkillStore returns the store, or nil when the daemon serves no Agent Skill.
func (s *HarnessCallbackService) agentSkillStore() agentskillstore.Store {
	return s.agentSkills()
}

// toolLister returns the lister of the catalog: the Agent Skills of the tenant,
// when the store is ready, and then the tools. The Agent Skills come first, so
// the default limit of a search does not hide them behind a large tool catalog.
func (s *HarnessCallbackService) toolLister(tools catalog.ToolLister) catalog.ToolLister {
	if store := s.agentSkillStore(); store != nil {
		return catalog.CombineListers(agentskillstore.ToolLister{Store: store}, tools)
	}
	return tools
}

// hideBlockedSkills returns the function that hides the Agent Skills that the
// deny list of the mission names. A denied Agent Skill is not found, and
// invoke_tool also refuses to load it. The deny list holds the same ids as
// for a tool. Only an id with the skill source is hidden here. A tool on the
// deny list is still listed and is refused at the call, as before.
func hideBlockedSkills(blocked []string) func(toolid.ID) bool {
	if len(blocked) == 0 {
		return nil
	}
	return func(id toolid.ID) bool {
		if id.Source != toolid.SourceSkill {
			return false
		}
		_, denied := metatool.MatchBlocked(blocked, id.Canonical())
		return denied
	}
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
