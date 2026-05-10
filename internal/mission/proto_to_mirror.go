package mission

import (
	"fmt"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	typespb "github.com/zero-day-ai/sdk/api/gen/gibson/types/v1"
)

// UnmarshalToMirror is a transitional helper that parses storage-layer
// JSON bytes (either canonical proto-shape from PR2+ writers or the
// legacy flat-mirror shape) and returns the mirror MissionDefinition
// expected by call sites that have not yet been type-swapped.
//
// It runs UnmarshalDefinitionJSON (proto-shape with legacy fallback) and
// then converts the resulting proto into the in-memory mirror struct
// via protoToMirrorDefinition.
//
// PR3 deletes this helper alongside the mirror types — call sites that
// can already work with *missionv1.MissionDefinition should use
// UnmarshalDefinitionJSON directly.
//
// Spec: mission-schema-canonicalization (PR2 of mirror→proto migration).
func UnmarshalToMirror(data []byte) (*MissionDefinition, error) {
	def, err := UnmarshalDefinitionJSON(data)
	if err != nil {
		return nil, err
	}
	return protoToMirrorDefinition(def)
}

// protoToMirrorDefinition is the inverse of mirrorDefinitionToProto.
// It is a transitional helper used by UnmarshalToMirror to feed
// pre-migration call sites that still consume *MissionDefinition.
//
// This is a deliberate copy of orchestrator.protoMissionToMissionDefinition
// kept in this package so the mission package can implement the dual-
// read path without an import cycle. PR3 removes both copies along
// with the mirror struct.
func protoToMirrorDefinition(p *missionv1.MissionDefinition) (*MissionDefinition, error) {
	if p == nil {
		return nil, fmt.Errorf("proto mission definition is nil")
	}

	nodes := make(map[string]*MissionNode, len(p.GetNodes()))
	for id, pn := range p.GetNodes() {
		mn, err := protoToMirrorNode(id, pn)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", id, err)
		}
		nodes[id] = mn
	}

	edges := make([]MissionEdge, 0, len(p.GetEdges()))
	for _, pe := range p.GetEdges() {
		edges = append(edges, MissionEdge{
			From:      pe.GetFrom(),
			To:        pe.GetTo(),
			Condition: pe.GetCondition(),
		})
	}

	var deps *MissionDependencies
	if d := p.GetDependencies(); d != nil {
		deps = &MissionDependencies{
			Agents:  d.GetAgents(),
			Tools:   d.GetTools(),
			Plugins: d.GetPlugins(),
		}
	}

	metadata := make(map[string]any, len(p.GetMetadata()))
	for k, v := range p.GetMetadata() {
		metadata[k] = v
	}

	out := &MissionDefinition{
		ID:           types.ID(p.GetId()),
		Name:         p.GetName(),
		Description:  p.GetDescription(),
		Version:      p.GetVersion(),
		TargetRef:    p.GetTargetRef(),
		Nodes:        nodes,
		Edges:        edges,
		EntryPoints:  p.GetEntryPoints(),
		ExitPoints:   p.GetExitPoints(),
		Metadata:     metadata,
		Dependencies: deps,
		Workspace:    protoToMirrorWorkspace(p.GetWorkspace()),
		Source:       p.GetSource(),
	}
	if ts := p.GetInstalledAt(); ts != nil {
		out.InstalledAt = ts.AsTime()
	}
	if ts := p.GetCreatedAt(); ts != nil {
		out.CreatedAt = ts.AsTime()
	}
	return out, nil
}

func protoToMirrorNode(id string, pn *missionv1.MissionNode) (*MissionNode, error) {
	if pn == nil {
		return nil, fmt.Errorf("proto node is nil")
	}

	var nodeType NodeType
	switch pn.GetType() {
	case missionv1.NodeType_NODE_TYPE_AGENT:
		nodeType = NodeTypeAgent
	case missionv1.NodeType_NODE_TYPE_TOOL:
		nodeType = NodeTypeTool
	case missionv1.NodeType_NODE_TYPE_PLUGIN:
		nodeType = NodeTypePlugin
	case missionv1.NodeType_NODE_TYPE_CONDITION:
		nodeType = NodeTypeCondition
	case missionv1.NodeType_NODE_TYPE_PARALLEL:
		nodeType = NodeTypeParallel
	case missionv1.NodeType_NODE_TYPE_JOIN:
		nodeType = NodeTypeJoin
	default:
		return nil, fmt.Errorf("unknown node type: %v", pn.GetType())
	}

	mn := &MissionNode{
		ID:           id,
		Type:         nodeType,
		Name:         pn.GetName(),
		Description:  pn.GetDescription(),
		Dependencies: pn.GetDependencies(),
	}
	if mn.ID == "" {
		mn.ID = pn.GetId()
	}

	if t := pn.GetTimeout(); t != nil {
		mn.Timeout = t.AsDuration()
	}

	if rp := pn.GetRetryPolicy(); rp != nil {
		mn.RetryPolicy = &RetryPolicy{
			MaxRetries: int(rp.GetMaxRetries()),
			Multiplier: rp.GetMultiplier(),
		}
		switch rp.GetBackoffStrategy() {
		case missionv1.BackoffStrategy_BACKOFF_STRATEGY_CONSTANT:
			mn.RetryPolicy.BackoffStrategy = BackoffConstant
		case missionv1.BackoffStrategy_BACKOFF_STRATEGY_LINEAR:
			mn.RetryPolicy.BackoffStrategy = BackoffLinear
		case missionv1.BackoffStrategy_BACKOFF_STRATEGY_EXPONENTIAL:
			mn.RetryPolicy.BackoffStrategy = BackoffExponential
		}
		if d := rp.GetInitialDelay(); d != nil {
			mn.RetryPolicy.InitialDelay = d.AsDuration()
		}
		if d := rp.GetMaxDelay(); d != nil {
			mn.RetryPolicy.MaxDelay = d.AsDuration()
		}
	}

	if md := pn.GetMetadata(); len(md) > 0 {
		mn.Metadata = make(map[string]any, len(md))
		for k, v := range md {
			mn.Metadata[k] = v
		}
	}

	switch nodeType {
	case NodeTypeAgent:
		if ac := pn.GetAgentConfig(); ac != nil {
			mn.AgentName = ac.GetAgentName()
			if t := ac.GetTask(); t != nil {
				mn.AgentTask = protoToMirrorTask(t)
			}
		}
	case NodeTypeTool:
		if tc := pn.GetToolConfig(); tc != nil {
			mn.ToolName = tc.GetToolName()
			if in := tc.GetInput(); len(in) > 0 {
				mn.ToolInput = make(map[string]any, len(in))
				for k, v := range in {
					mn.ToolInput[k] = v
				}
			}
		}
	case NodeTypePlugin:
		if pc := pn.GetPluginConfig(); pc != nil {
			mn.PluginName = pc.GetPluginName()
			mn.PluginMethod = pc.GetMethod()
			if pp := pc.GetParams(); len(pp) > 0 {
				mn.PluginParams = make(map[string]any, len(pp))
				for k, v := range pp {
					mn.PluginParams[k] = v
				}
			}
		}
	case NodeTypeCondition:
		if cc := pn.GetConditionConfig(); cc != nil {
			mn.Condition = &NodeCondition{
				Expression:  cc.GetExpression(),
				TrueBranch:  cc.GetTrueBranch(),
				FalseBranch: cc.GetFalseBranch(),
			}
		}
	case NodeTypeParallel:
		if pc := pn.GetParallelConfig(); pc != nil {
			subs := make([]*MissionNode, 0, len(pc.GetSubNodes()))
			for _, spn := range pc.GetSubNodes() {
				sub, err := protoToMirrorNode(spn.GetId(), spn)
				if err != nil {
					return nil, fmt.Errorf("sub-node %s: %w", spn.GetId(), err)
				}
				subs = append(subs, sub)
			}
			mn.SubNodes = subs
		}
	}

	return mn, nil
}

func protoToMirrorWorkspace(p *missionv1.WorkspaceConfig) *WorkspaceConfig {
	if p == nil {
		return nil
	}
	out := &WorkspaceConfig{
		Settings: WorkspaceSettings{
			CleanupOnComplete: p.GetSettings().GetCleanupOnComplete(),
			UseWorktrees:      p.GetSettings().GetUseWorktrees(),
			LSPEnabled:        p.GetSettings().GetLspEnabled(),
			BaseDirectory:     p.GetSettings().GetBaseDirectory(),
		},
	}
	if d := p.GetSettings().GetLspTimeout(); d != nil {
		out.Settings.LSPTimeout = d.AsDuration()
	}
	for _, r := range p.GetRepositories() {
		out.Repositories = append(out.Repositories, RepositoryConfig{
			Name:           r.GetName(),
			URL:            r.GetUrl(),
			Branch:         r.GetBranch(),
			CredentialName: r.GetCredentialName(),
			Shallow:        r.GetShallow(),
			DependsOn:      r.GetDependsOn(),
		})
	}
	return out
}

func protoToMirrorTask(p *typespb.Task) *agent.Task {
	if p == nil {
		return nil
	}
	t := &agent.Task{
		ID:   types.ID(p.GetId()),
		Goal: p.GetGoal(),
	}
	if ctx := p.GetContext(); len(ctx) > 0 {
		t.Context = make(map[string]any, len(ctx))
		for k, v := range ctx {
			t.Context[k] = protoTypedValueToAny(v)
		}
	}
	return t
}

func protoTypedValueToAny(tv *commonpb.TypedValue) any {
	if tv == nil {
		return nil
	}
	switch v := tv.GetKind().(type) {
	case *commonpb.TypedValue_StringValue:
		return v.StringValue
	case *commonpb.TypedValue_IntValue:
		return v.IntValue
	case *commonpb.TypedValue_DoubleValue:
		return v.DoubleValue
	case *commonpb.TypedValue_BoolValue:
		return v.BoolValue
	case *commonpb.TypedValue_BytesValue:
		return v.BytesValue
	case *commonpb.TypedValue_ArrayValue:
		if v.ArrayValue == nil {
			return nil
		}
		list := make([]any, len(v.ArrayValue.GetItems()))
		for i, item := range v.ArrayValue.GetItems() {
			list[i] = protoTypedValueToAny(item)
		}
		return list
	case *commonpb.TypedValue_MapValue:
		if v.MapValue == nil {
			return nil
		}
		m := make(map[string]any, len(v.MapValue.GetEntries()))
		for k, item := range v.MapValue.GetEntries() {
			m[k] = protoTypedValueToAny(item)
		}
		return m
	default:
		return nil
	}
}
