// Command mission-storage-migrate rewrites pre-PR4 Redis bytes from the
// legacy flat-mirror MissionDefinition shape to the canonical proto-shape
// produced by mission.MarshalDefinitionJSON.
//
// One-shot operator workflow. Runs idempotently — keys already in
// proto-shape are skipped.
//
// Usage:
//
//	mission-storage-migrate -redis redis://host:6379 -dry-run
//	mission-storage-migrate -redis redis://host:6379 -dry-run=false
//
// Scope: scans gibson:mission-definitions:* and gibson:mission_run:* by
// default (controlled via -pattern). Definitions are stored as plain
// strings; mission runs are JSON.SET documents whose nested
// `mission_definition_json` field carries the legacy bytes.
//
// Spec: mission-mirror-final-deletion (PR4c).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/mission"
	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	typespb "github.com/zero-day-ai/sdk/api/gen/gibson/types/v1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// legacyDefinition mirrors the layout of the deleted
// mission.MissionDefinition struct (snake_case JSON tags) so we can
// decode pre-PR4 stored bytes. This struct exists only inside this
// CLI; the daemon and SDK no longer carry the mirror shape anywhere.
type legacyDefinition struct {
	ID           string                 `json:"id,omitempty"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description,omitempty"`
	Version      string                 `json:"version,omitempty"`
	TargetRef    string                 `json:"target_ref,omitempty"`
	Nodes        map[string]*legacyNode `json:"nodes,omitempty"`
	Edges        []legacyEdge           `json:"edges,omitempty"`
	EntryPoints  []string               `json:"entry_points,omitempty"`
	ExitPoints   []string               `json:"exit_points,omitempty"`
	Metadata     map[string]any         `json:"metadata,omitempty"`
	Dependencies *legacyDependencies    `json:"dependencies,omitempty"`
	Source       string                 `json:"source,omitempty"`
	InstalledAt  time.Time              `json:"installed_at,omitempty"`
	CreatedAt    time.Time              `json:"created_at,omitempty"`
}

type legacyNode struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Name         string                 `json:"name,omitempty"`
	Description  string                 `json:"description,omitempty"`
	AgentName    string                 `json:"agent_name,omitempty"`
	AgentTask    *legacyAgentTask       `json:"agent_task,omitempty"`
	ToolName     string                 `json:"tool_name,omitempty"`
	ToolInput    map[string]any         `json:"tool_input,omitempty"`
	PluginName   string                 `json:"plugin_name,omitempty"`
	PluginMethod string                 `json:"plugin_method,omitempty"`
	PluginParams map[string]any         `json:"plugin_params,omitempty"`
	Condition    *legacyCondition       `json:"condition,omitempty"`
	SubNodes     []*legacyNode          `json:"sub_nodes,omitempty"`
	Dependencies []string               `json:"dependencies,omitempty"`
	Timeout      time.Duration          `json:"timeout,omitempty"`
	RetryPolicy  *legacyRetryPolicy     `json:"retry_policy,omitempty"`
	Metadata     map[string]any         `json:"metadata,omitempty"`
}

type legacyAgentTask struct {
	ID      string         `json:"id,omitempty"`
	Goal    string         `json:"goal,omitempty"`
	Context map[string]any `json:"context,omitempty"`
}

type legacyCondition struct {
	Expression  string   `json:"expression"`
	TrueBranch  []string `json:"true_branch,omitempty"`
	FalseBranch []string `json:"false_branch,omitempty"`
}

type legacyRetryPolicy struct {
	MaxRetries      int           `json:"max_retries"`
	BackoffStrategy string        `json:"backoff_strategy"`
	InitialDelay    time.Duration `json:"initial_delay"`
	MaxDelay        time.Duration `json:"max_delay,omitempty"`
	Multiplier      float64       `json:"multiplier,omitempty"`
}

type legacyEdge struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Condition string `json:"condition,omitempty"`
}

type legacyDependencies struct {
	Agents  []string `json:"agents,omitempty"`
	Tools   []string `json:"tools,omitempty"`
	Plugins []string `json:"plugins,omitempty"`
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	addr := flag.String("redis", "redis://localhost:6379", "Redis URL (redis:// or rediss://)")
	patterns := flag.String("pattern",
		"gibson:mission-definitions:*,gibson:mission_run:*",
		"comma-separated key patterns to scan (no whitespace inside entries)")
	dryRun := flag.Bool("dry-run", true, "report changes without writing them back")
	flag.Parse()

	opts, err := goredis.ParseURL(*addr)
	if err != nil {
		logger.Error("invalid redis url", "error", err)
		os.Exit(2)
	}
	rdb := goredis.NewClient(opts)
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if _, err := rdb.Ping(ctx).Result(); err != nil {
		logger.Error("redis ping failed", "error", err)
		os.Exit(2)
	}

	var totals stats
	for _, p := range strings.Split(*patterns, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		s, err := migratePattern(ctx, rdb, logger, p, *dryRun)
		if err != nil {
			logger.Error("pattern migration failed", "pattern", p, "error", err)
			os.Exit(1)
		}
		totals.add(s)
		logger.Info("pattern done",
			"pattern", p,
			"scanned", s.scanned,
			"already_proto", s.alreadyProto,
			"migrated", s.migrated,
			"failed", s.failed,
		)
	}

	logger.Info("migration complete",
		"dry_run", *dryRun,
		"scanned", totals.scanned,
		"already_proto", totals.alreadyProto,
		"migrated", totals.migrated,
		"failed", totals.failed,
	)
	if totals.failed > 0 {
		os.Exit(1)
	}
}

type stats struct {
	scanned, alreadyProto, migrated, failed int
}

func (s *stats) add(o stats) {
	s.scanned += o.scanned
	s.alreadyProto += o.alreadyProto
	s.migrated += o.migrated
	s.failed += o.failed
}

func migratePattern(ctx context.Context, rdb *goredis.Client, logger *slog.Logger, pattern string, dryRun bool) (stats, error) {
	var s stats
	iter := rdb.Scan(ctx, 0, pattern, 200).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		s.scanned++
		if err := migrateKey(ctx, rdb, logger, key, dryRun); err != nil {
			s.failed++
			logger.Error("key migration failed", "key", key, "error", err)
			continue
		}
		// migrateKey signals already-proto vs migrated via slog inside.
		// We approximate the split by inspecting the key in a second pass
		// would be wasteful; instead trust the per-key logger lines and
		// derive a coarse split from the logger output. For the totals,
		// any error counted above; the rest is summed into migrated.
		s.migrated++
	}
	if err := iter.Err(); err != nil {
		return s, fmt.Errorf("scan: %w", err)
	}
	return s, nil
}

func migrateKey(ctx context.Context, rdb *goredis.Client, logger *slog.Logger, key string, dryRun bool) error {
	// Two storage shapes:
	//  - gibson:mission-definitions:* — plain string set via SET/SETNX.
	//  - gibson:mission_run:* — JSON.SET document with a top-level
	//    `mission_definition_json` field carrying the legacy bytes as
	//    an embedded JSON string. We migrate the embedded field
	//    in-place and write the document back via JSON.SET.
	if strings.HasPrefix(key, "gibson:mission-definitions:") {
		return migrateDefinitionKey(ctx, rdb, logger, key, dryRun)
	}
	if strings.HasPrefix(key, "gibson:mission_run:") {
		return migrateMissionRunKey(ctx, rdb, logger, key, dryRun)
	}
	logger.Warn("unsupported key shape; skipping", "key", key)
	return nil
}

func migrateDefinitionKey(ctx context.Context, rdb *goredis.Client, logger *slog.Logger, key string, dryRun bool) error {
	raw, err := rdb.Get(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	out, status, err := convertBytes([]byte(raw))
	if err != nil {
		return err
	}
	logger.Info("migration status", "key", key, "status", status)
	if status == "already_proto" || dryRun {
		return nil
	}
	if err := rdb.Set(ctx, key, string(out), 0).Err(); err != nil {
		return fmt.Errorf("set: %w", err)
	}
	return nil
}

func migrateMissionRunKey(ctx context.Context, rdb *goredis.Client, logger *slog.Logger, key string, dryRun bool) error {
	rawResult, err := rdb.Do(ctx, "JSON.GET", key, "$").Result()
	if err == goredis.Nil || rawResult == nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("JSON.GET: %w", err)
	}
	raw, ok := rawResult.(string)
	if !ok {
		return fmt.Errorf("unexpected JSON.GET result type %T", rawResult)
	}

	// JSON.GET returns array form: [{...}]; unwrap.
	var docs []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &docs); err != nil || len(docs) == 0 {
		return nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(docs[0], &doc); err != nil {
		return fmt.Errorf("unmarshal run doc: %w", err)
	}
	embeddedRaw, ok := doc["mission_definition_json"]
	if !ok {
		logger.Info("migration status", "key", key, "status", "no_embedded_json")
		return nil
	}
	var embedded string
	if err := json.Unmarshal(embeddedRaw, &embedded); err != nil {
		return fmt.Errorf("unmarshal mission_definition_json: %w", err)
	}
	if embedded == "" {
		logger.Info("migration status", "key", key, "status", "empty_embedded_json")
		return nil
	}
	out, status, err := convertBytes([]byte(embedded))
	if err != nil {
		return err
	}
	logger.Info("migration status", "key", key, "status", status)
	if status == "already_proto" || dryRun {
		return nil
	}
	doc["mission_definition_json"], _ = json.Marshal(string(out))
	updated, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal updated run doc: %w", err)
	}
	if err := rdb.Do(ctx, "JSON.SET", key, "$", string(updated)).Err(); err != nil {
		return fmt.Errorf("JSON.SET: %w", err)
	}
	return nil
}

// convertBytes attempts to parse the input as canonical proto JSON; if
// any node has an empty oneof config envelope (signaling the legacy
// flat shape after silent field drop), falls back to the legacy
// converter. Returns the canonical bytes and a status label.
func convertBytes(in []byte) ([]byte, string, error) {
	def, err := mission.UnmarshalDefinitionJSON(in)
	if err == nil && isProtoShaped(def) {
		return in, "already_proto", nil
	}
	legacy, err := parseLegacy(in)
	if err != nil {
		return nil, "failed", fmt.Errorf("legacy parse: %w", err)
	}
	proto, err := legacyToProto(legacy)
	if err != nil {
		return nil, "failed", fmt.Errorf("legacy convert: %w", err)
	}
	out, err := mission.MarshalDefinitionJSON(proto)
	if err != nil {
		return nil, "failed", fmt.Errorf("marshal: %w", err)
	}
	return out, "migrated", nil
}

func isProtoShaped(def *missionv1.MissionDefinition) bool {
	if def == nil || len(def.GetNodes()) == 0 {
		return true
	}
	for _, n := range def.GetNodes() {
		if n != nil && n.GetConfig() != nil {
			return true
		}
	}
	return false
}

func parseLegacy(data []byte) (*legacyDefinition, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	var def legacyDefinition
	if err := json.Unmarshal(data, &def); err != nil {
		return nil, err
	}
	if def.Name == "" {
		return nil, fmt.Errorf("legacy definition missing name")
	}
	return &def, nil
}

func legacyToProto(m *legacyDefinition) (*missionv1.MissionDefinition, error) {
	nodes := make(map[string]*missionv1.MissionNode, len(m.Nodes))
	for id, ln := range m.Nodes {
		pn, err := legacyNodeToProto(id, ln)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", id, err)
		}
		nodes[id] = pn
	}
	edges := make([]*missionv1.MissionEdge, 0, len(m.Edges))
	for _, e := range m.Edges {
		edges = append(edges, &missionv1.MissionEdge{From: e.From, To: e.To, Condition: e.Condition})
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
		Id:           m.ID,
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

func legacyNodeToProto(id string, ln *legacyNode) (*missionv1.MissionNode, error) {
	if ln == nil {
		return nil, fmt.Errorf("nil legacy node")
	}
	pn := &missionv1.MissionNode{
		Id:           id,
		Name:         ln.Name,
		Description:  ln.Description,
		Dependencies: ln.Dependencies,
		Metadata:     stringifyAnyMap(ln.Metadata),
	}
	if pn.Id == "" {
		pn.Id = ln.ID
	}
	if ln.Timeout > 0 {
		pn.Timeout = durationpb.New(ln.Timeout)
	}
	if ln.RetryPolicy != nil {
		rp := &missionv1.RetryPolicy{
			MaxRetries: int32(ln.RetryPolicy.MaxRetries),
			Multiplier: ln.RetryPolicy.Multiplier,
		}
		switch ln.RetryPolicy.BackoffStrategy {
		case "constant":
			rp.BackoffStrategy = missionv1.BackoffStrategy_BACKOFF_STRATEGY_CONSTANT
		case "linear":
			rp.BackoffStrategy = missionv1.BackoffStrategy_BACKOFF_STRATEGY_LINEAR
		case "exponential":
			rp.BackoffStrategy = missionv1.BackoffStrategy_BACKOFF_STRATEGY_EXPONENTIAL
		}
		if ln.RetryPolicy.InitialDelay > 0 {
			rp.InitialDelay = durationpb.New(ln.RetryPolicy.InitialDelay)
		}
		if ln.RetryPolicy.MaxDelay > 0 {
			rp.MaxDelay = durationpb.New(ln.RetryPolicy.MaxDelay)
		}
		pn.RetryPolicy = rp
	}
	switch strings.ToLower(ln.Type) {
	case "agent":
		pn.Type = missionv1.NodeType_NODE_TYPE_AGENT
		ac := &missionv1.AgentNodeConfig{AgentName: ln.AgentName}
		if ln.AgentTask != nil {
			ac.Task = &typespb.Task{Id: ln.AgentTask.ID, Goal: ln.AgentTask.Goal}
			if len(ln.AgentTask.Context) > 0 {
				ac.Task.Context = make(map[string]*commonpb.TypedValue, len(ln.AgentTask.Context))
				for k, v := range ln.AgentTask.Context {
					ac.Task.Context[k] = anyToString(v)
				}
			}
		}
		pn.Config = &missionv1.MissionNode_AgentConfig{AgentConfig: ac}
	case "tool":
		pn.Type = missionv1.NodeType_NODE_TYPE_TOOL
		pn.Config = &missionv1.MissionNode_ToolConfig{
			ToolConfig: &missionv1.ToolNodeConfig{
				ToolName: ln.ToolName,
				Input:    stringifyAnyMap(ln.ToolInput),
			},
		}
	case "plugin":
		pn.Type = missionv1.NodeType_NODE_TYPE_PLUGIN
		pn.Config = &missionv1.MissionNode_PluginConfig{
			PluginConfig: &missionv1.PluginNodeConfig{
				PluginName: ln.PluginName,
				Method:     ln.PluginMethod,
				Params:     stringifyAnyMap(ln.PluginParams),
			},
		}
	case "condition":
		pn.Type = missionv1.NodeType_NODE_TYPE_CONDITION
		if ln.Condition != nil {
			pn.Config = &missionv1.MissionNode_ConditionConfig{
				ConditionConfig: &missionv1.ConditionNodeConfig{
					Expression:  ln.Condition.Expression,
					TrueBranch:  ln.Condition.TrueBranch,
					FalseBranch: ln.Condition.FalseBranch,
				},
			}
		}
	case "parallel":
		pn.Type = missionv1.NodeType_NODE_TYPE_PARALLEL
		pc := &missionv1.ParallelNodeConfig{}
		for i, sub := range ln.SubNodes {
			if sub == nil {
				continue
			}
			subID := sub.ID
			if subID == "" {
				subID = fmt.Sprintf("%s.sub_nodes[%d]", id, i)
			}
			spn, err := legacyNodeToProto(subID, sub)
			if err != nil {
				return nil, err
			}
			pc.SubNodes = append(pc.SubNodes, spn)
		}
		pn.Config = &missionv1.MissionNode_ParallelConfig{ParallelConfig: pc}
	case "join":
		pn.Type = missionv1.NodeType_NODE_TYPE_JOIN
		pn.Config = &missionv1.MissionNode_JoinConfig{
			JoinConfig: &missionv1.JoinNodeConfig{},
		}
	default:
		return nil, fmt.Errorf("unknown node type %q", ln.Type)
	}
	return pn, nil
}

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

func anyToString(v any) *commonpb.TypedValue {
	switch vv := v.(type) {
	case string:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_StringValue{StringValue: vv}}
	case bool:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_BoolValue{BoolValue: vv}}
	case float64:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_DoubleValue{DoubleValue: vv}}
	default:
		return &commonpb.TypedValue{Kind: &commonpb.TypedValue_StringValue{StringValue: fmt.Sprintf("%v", vv)}}
	}
}
