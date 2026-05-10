package mission

import (
	"fmt"

	"github.com/zero-day-ai/gibson/internal/agent"
	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	typespb "github.com/zero-day-ai/sdk/api/gen/gibson/types/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// LegacyMirrorJSONToProto parses legacy flat-mirror-shape JSON bytes
// (produced by encoding/json on *mission.MissionDefinition before the
// PR2 mirror→proto migration) and returns the equivalent
// *missionv1.MissionDefinition.
//
// This is the storage-migration path used by cmd/mission-storage-migrate
// to rewrite already-stored MissionDefinitionJSON columns from the flat
// mirror shape to the canonical proto-shape that PR2's writers emit.
//
// PR3 deletes this function (along with the rest of the mirror struct)
// once stored data is fully migrated. New code paths should use
// MarshalDefinitionJSON / UnmarshalDefinitionJSON directly.
func LegacyMirrorJSONToProto(data []byte) (*missionv1.MissionDefinition, error) {
	mirror, err := ParseDefinitionFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("legacy mirror parse: %w", err)
	}
	return mirrorDefinitionToProto(mirror)
}

// mirrorDefinitionToProto walks a mirror MissionDefinition and emits the
// equivalent proto definition, populating each MissionNode's oneof
// config envelope per node type.
//
// Inverse of orchestrator.protoMissionToMissionDefinition.
func mirrorDefinitionToProto(m *MissionDefinition) (*missionv1.MissionDefinition, error) {
	if m == nil {
		return nil, fmt.Errorf("mirror mission definition is nil")
	}

	nodes := make(map[string]*missionv1.MissionNode, len(m.Nodes))
	for id, mn := range m.Nodes {
		pn, err := mirrorNodeToProto(id, mn)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", id, err)
		}
		nodes[id] = pn
	}

	edges := make([]*missionv1.MissionEdge, 0, len(m.Edges))
	for _, e := range m.Edges {
		edges = append(edges, &missionv1.MissionEdge{
			From:      e.From,
			To:        e.To,
			Condition: e.Condition,
		})
	}

	var deps *missionv1.MissionDependencies
	if m.Dependencies != nil {
		deps = &missionv1.MissionDependencies{
			Agents:  m.Dependencies.Agents,
			Tools:   m.Dependencies.Tools,
			Plugins: m.Dependencies.Plugins,
		}
	}

	out := &missionv1.MissionDefinition{
		Id:           string(m.ID),
		Name:         m.Name,
		Description:  m.Description,
		Version:      m.Version,
		TargetRef:    m.TargetRef,
		Nodes:        nodes,
		Edges:        edges,
		EntryPoints:  m.EntryPoints,
		ExitPoints:   m.ExitPoints,
		Metadata:     stringifyAnyMap(m.Metadata),
		Dependencies: deps,
		Workspace:    mirrorWorkspaceToProto(m.Workspace),
		Source:       m.Source,
	}
	if !m.InstalledAt.IsZero() {
		out.InstalledAt = timestamppb.New(m.InstalledAt)
	}
	if !m.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(m.CreatedAt)
	}
	return out, nil
}

// mirrorNodeToProto inverts orchestrator.protoNodeToMissionNode.
// Per-noun fields (AgentName, ToolName, …) on the flat mirror are
// folded into the proto's oneof config envelope according to node type.
func mirrorNodeToProto(id string, mn *MissionNode) (*missionv1.MissionNode, error) {
	if mn == nil {
		return nil, fmt.Errorf("mirror node is nil")
	}

	pn := &missionv1.MissionNode{
		Id:           id,
		Name:         mn.Name,
		Description:  mn.Description,
		Dependencies: mn.Dependencies,
		Metadata:     stringifyAnyMap(mn.Metadata),
	}
	if pn.Id == "" {
		pn.Id = mn.ID
	}

	switch mn.Type {
	case NodeTypeAgent:
		pn.Type = missionv1.NodeType_NODE_TYPE_AGENT
	case NodeTypeTool:
		pn.Type = missionv1.NodeType_NODE_TYPE_TOOL
	case NodeTypePlugin:
		pn.Type = missionv1.NodeType_NODE_TYPE_PLUGIN
	case NodeTypeCondition:
		pn.Type = missionv1.NodeType_NODE_TYPE_CONDITION
	case NodeTypeParallel:
		pn.Type = missionv1.NodeType_NODE_TYPE_PARALLEL
	case NodeTypeJoin:
		pn.Type = missionv1.NodeType_NODE_TYPE_JOIN
	default:
		return nil, fmt.Errorf("unknown node type: %s", mn.Type)
	}

	if mn.Timeout > 0 {
		pn.Timeout = durationpb.New(mn.Timeout)
	}

	if mn.RetryPolicy != nil {
		rp := &missionv1.RetryPolicy{
			MaxRetries: int32(mn.RetryPolicy.MaxRetries),
			Multiplier: mn.RetryPolicy.Multiplier,
		}
		switch mn.RetryPolicy.BackoffStrategy {
		case BackoffConstant:
			rp.BackoffStrategy = missionv1.BackoffStrategy_BACKOFF_STRATEGY_CONSTANT
		case BackoffLinear:
			rp.BackoffStrategy = missionv1.BackoffStrategy_BACKOFF_STRATEGY_LINEAR
		case BackoffExponential:
			rp.BackoffStrategy = missionv1.BackoffStrategy_BACKOFF_STRATEGY_EXPONENTIAL
		}
		if mn.RetryPolicy.InitialDelay > 0 {
			rp.InitialDelay = durationpb.New(mn.RetryPolicy.InitialDelay)
		}
		if mn.RetryPolicy.MaxDelay > 0 {
			rp.MaxDelay = durationpb.New(mn.RetryPolicy.MaxDelay)
		}
		pn.RetryPolicy = rp
	}

	switch mn.Type {
	case NodeTypeAgent:
		ac := &missionv1.AgentNodeConfig{AgentName: mn.AgentName}
		if mn.AgentTask != nil {
			ac.Task = mirrorTaskToProto(mn.AgentTask)
		}
		pn.Config = &missionv1.MissionNode_AgentConfig{AgentConfig: ac}

	case NodeTypeTool:
		pn.Config = &missionv1.MissionNode_ToolConfig{
			ToolConfig: &missionv1.ToolNodeConfig{
				ToolName: mn.ToolName,
				Input:    stringifyAnyMap(mn.ToolInput),
			},
		}

	case NodeTypePlugin:
		pn.Config = &missionv1.MissionNode_PluginConfig{
			PluginConfig: &missionv1.PluginNodeConfig{
				PluginName: mn.PluginName,
				Method:     mn.PluginMethod,
				Params:     stringifyAnyMap(mn.PluginParams),
			},
		}

	case NodeTypeCondition:
		if mn.Condition != nil {
			pn.Config = &missionv1.MissionNode_ConditionConfig{
				ConditionConfig: &missionv1.ConditionNodeConfig{
					Expression:  mn.Condition.Expression,
					TrueBranch:  mn.Condition.TrueBranch,
					FalseBranch: mn.Condition.FalseBranch,
				},
			}
		}

	case NodeTypeParallel:
		pc := &missionv1.ParallelNodeConfig{}
		for i, sub := range mn.SubNodes {
			if sub == nil {
				continue
			}
			subID := sub.ID
			if subID == "" {
				subID = fmt.Sprintf("%s.sub_nodes[%d]", id, i)
			}
			subPN, err := mirrorNodeToProto(subID, sub)
			if err != nil {
				return nil, fmt.Errorf("sub-node %d: %w", i, err)
			}
			pc.SubNodes = append(pc.SubNodes, subPN)
		}
		pn.Config = &missionv1.MissionNode_ParallelConfig{ParallelConfig: pc}

	case NodeTypeJoin:
		// Legacy mirror has no JoinNodeConfig fields — JOIN was added
		// in mission-verb-noun-registry alongside the proto canonical
		// form, after the mirror was already deployed. Emit an empty
		// JoinConfig so submit-time validation can still distinguish
		// JOIN from configless types; downstream callers needing a
		// non-empty wait_for must regenerate from YAML.
		pn.Config = &missionv1.MissionNode_JoinConfig{
			JoinConfig: &missionv1.JoinNodeConfig{},
		}
	}

	return pn, nil
}

// mirrorWorkspaceToProto folds the mirror's WorkspaceConfig + nested
// RepositoryConfig / WorkspaceSettings into the proto equivalent. The
// proto LSPTimeout is google.protobuf.Duration; the mirror's is
// time.Duration, encoded directly.
func mirrorWorkspaceToProto(m *WorkspaceConfig) *missionv1.WorkspaceConfig {
	if m == nil {
		return nil
	}
	out := &missionv1.WorkspaceConfig{}
	for _, r := range m.Repositories {
		out.Repositories = append(out.Repositories, &missionv1.RepositoryConfig{
			Name:           r.Name,
			Url:            r.URL,
			Branch:         r.Branch,
			CredentialName: r.CredentialName,
			Shallow:        r.Shallow,
			DependsOn:      r.DependsOn,
		})
	}
	settings := &missionv1.WorkspaceSettings{
		CleanupOnComplete: m.Settings.CleanupOnComplete,
		UseWorktrees:      m.Settings.UseWorktrees,
		LspEnabled:        m.Settings.LSPEnabled,
		BaseDirectory:     m.Settings.BaseDirectory,
	}
	if m.Settings.LSPTimeout > 0 {
		settings.LspTimeout = durationpb.New(m.Settings.LSPTimeout)
	}
	out.Settings = settings
	return out
}

// mirrorTaskToProto inverts orchestrator.protoTaskToAgentTask.
func mirrorTaskToProto(t *agent.Task) *typespb.Task {
	if t == nil {
		return nil
	}
	pt := &typespb.Task{
		Id:   string(t.ID),
		Goal: t.Goal,
	}
	if len(t.Context) > 0 {
		pt.Context = make(map[string]*commonpb.TypedValue, len(t.Context))
		for k, v := range t.Context {
			pt.Context[k] = anyToTypedValue(v)
		}
	}
	return pt
}

// stringifyAnyMap coerces a map[string]any into map[string]string, the
// shape proto Metadata / ToolInput / PluginParams expect. String values
// pass through untouched; everything else is rendered via fmt.Sprintf
// with %v to preserve the legacy mirror's lossy round-trip behavior.
func stringifyAnyMap(m map[string]any) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		switch vv := v.(type) {
		case nil:
			out[k] = ""
		case string:
			out[k] = vv
		default:
			out[k] = fmt.Sprintf("%v", vv)
		}
	}
	return out
}

// anyToTypedValue inverts orchestrator.typedValueToAny. Used to lift
// agent.Task.Context (map[string]any) into the proto Task.Context
// (map[string]*TypedValue).
func anyToTypedValue(v any) *commonpb.TypedValue {
	if v == nil {
		return nil
	}
	switch vv := v.(type) {
	case string:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_StringValue{StringValue: vv}}
	case bool:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_BoolValue{BoolValue: vv}}
	case int:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_IntValue{IntValue: int64(vv)}}
	case int32:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_IntValue{IntValue: int64(vv)}}
	case int64:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_IntValue{IntValue: vv}}
	case float32:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_DoubleValue{DoubleValue: float64(vv)}}
	case float64:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_DoubleValue{DoubleValue: vv}}
	case []byte:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_BytesValue{BytesValue: vv}}
	case []any:
		items := make([]*commonpb.TypedValue, 0, len(vv))
		for _, item := range vv {
			items = append(items, anyToTypedValue(item))
		}
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_ArrayValue{
				ArrayValue: &commonpb.TypedArray{Items: items},
			},
		}
	case map[string]any:
		entries := make(map[string]*commonpb.TypedValue, len(vv))
		for k, item := range vv {
			entries[k] = anyToTypedValue(item)
		}
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_MapValue{
				MapValue: &commonpb.TypedMap{Entries: entries},
			},
		}
	default:
		// Unknown type — render via fmt.Sprintf so the value at least
		// survives as a string. JSON-decoded numbers arrive as
		// float64 above; this default covers fallback for json.Number
		// and similar custom types.
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_StringValue{StringValue: fmt.Sprintf("%v", vv)},
		}
	}
}
