package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/infra/contextkeys"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestOTelMissionTracer_AttributionEndToEnd exercises the full tracer path
// (StartMissionTrace + LogDecision) with a context carrying every identity
// key the design requires, and asserts the resulting spans carry the full
// canonical attribute set.
//
// This is the spec's Requirement 1 end-to-end contract: user_id,
// initiator_user_id, executor_user_id, mission_id, run_id, agent_id,
// tenant_id, component_scope, gen_ai.request.model, and gen_ai.system all
// land on the exported span metadata so Langfuse can aggregate per-user.
func TestOTelMissionTracer_AttributionEndToEnd(t *testing.T) {
	// ------------------------------------------------------------------
	// Set up the tracer with an in-memory exporter so we can inspect
	// exported spans as structured data after the test exercises the
	// real tracer methods.
	// ------------------------------------------------------------------
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	metricReader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(metricReader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	tracer := NewOTelMissionTracer(tp, mp, nil)
	require.NotNil(t, tracer)

	// ------------------------------------------------------------------
	// Build a fully-populated context: tenant, acting user, initiator
	// user, executor user, component scope, plus mission / run / agent
	// identifiers via the contextkeys package. In production this
	// context is assembled over several layers (ext-authz interceptor
	// for tenant + acting, mission controller for initiator, sub-agent
	// dispatch for executor) — for the test we stitch them in one step.
	// ------------------------------------------------------------------
	ctx := context.Background()
	ctx = auth.ContextWithTenantString(ctx, "acme-corp")
	ctx = auth.ContextWithActingUser(ctx, "user-alice")
	ctx = auth.ContextWithInitiatorUser(ctx, "user-alice")
	ctx = auth.ContextWithExecutorUser(ctx, "user-bob")
	ctx = auth.ContextWithComponentScope(ctx, "agent_principal:delegated-abc")

	ctx = context.WithValue(ctx, contextkeys.MissionID, "mission-42")
	ctx = contextkeys.WithMissionRunID(ctx, "run-42-1")
	ctx = context.WithValue(ctx, contextkeys.AgentName, "triage-agent")
	ctx = contextkeys.WithAgentRunID(ctx, "agentrun-42-1-001")
	ctx = ContextWithSlotName(ctx, "reasoner")

	// ------------------------------------------------------------------
	// 1. Start a mission trace — produces the root mission span.
	// ------------------------------------------------------------------
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-attribution-mission",
		Objective: "Verify user attribution flows through the tracer",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	_, missionSpan, err := tracer.StartMissionTrace(ctx, mission)
	require.NoError(t, err)
	require.NotNil(t, missionSpan)

	// ------------------------------------------------------------------
	// 2. Log a decision — produces a child GenAI span.
	// ------------------------------------------------------------------
	decision := &schema.Decision{
		ID:               types.NewID(),
		MissionID:        mission.ID,
		Iteration:        1,
		Timestamp:        time.Now(),
		Action:           schema.DecisionActionExecuteAgent,
		TargetNodeID:     "node-1",
		Reasoning:        "Test reasoning",
		Confidence:       0.95,
		PromptTokens:     100,
		CompletionTokens: 50,
		LatencyMs:        200,
		Model:            "claude-sonnet-4",
	}

	decisionLog := &DecisionLog{
		Decision: decision,
		Model:    "claude-sonnet-4",
		RequestMeta: &RequestMetadata{
			Model:    "claude-sonnet-4",
			Provider: "anthropic",
			SlotName: "reasoner",
		},
	}

	require.NoError(t, tracer.LogDecision(ctx, missionSpan, decisionLog))

	// Close the mission span so it exports.
	missionSpan.span.End()

	// ------------------------------------------------------------------
	// Collect exported spans and index them by name for assertions.
	// StartMissionTrace creates one span (SpanMissionExecute); LogDecision
	// creates one GenAI span. Both should carry the full identity set.
	// ------------------------------------------------------------------
	spans := exporter.GetSpans()
	require.GreaterOrEqual(t, len(spans), 2, "expected at least mission + decision spans")

	byName := map[string]map[string]attribute.Value{}
	for _, s := range spans {
		attrs := map[string]attribute.Value{}
		for _, a := range s.Attributes {
			attrs[string(a.Key)] = a.Value
		}
		byName[s.Name] = attrs
	}

	// ------------------------------------------------------------------
	// Assert on the mission span.
	// ------------------------------------------------------------------
	missionAttrs, ok := byName[SpanMissionExecute]
	require.True(t, ok, "mission span not present; got spans: %v", spanNames(spans))

	assert.Equal(t, "acme-corp", missionAttrs[AttrTenantID].AsString(), "tenant_id on mission span")
	assert.Equal(t, "user-alice", missionAttrs[AttrUserID].AsString(), "user_id (ActingUser) on mission span")
	assert.Equal(t, "user-alice", missionAttrs[AttrInitiatorUserID].AsString(), "initiator_user_id on mission span")
	assert.Equal(t, "user-bob", missionAttrs[AttrExecutorUserID].AsString(), "executor_user_id on mission span")
	assert.Equal(t, "agent_principal:delegated-abc", missionAttrs[AttrComponentScope].AsString(), "component_scope on mission span")
	assert.Equal(t, "mission-42", missionAttrs[AttrMissionID].AsString(), "mission_id on mission span")
	assert.Equal(t, "run-42-1", missionAttrs[AttrRunID].AsString(), "run_id on mission span")
	assert.Equal(t, "triage-agent", missionAttrs[AttrAgentID].AsString(), "agent_id on mission span")
	assert.Equal(t, "reasoner", missionAttrs[AttrSlotName].AsString(), "slot_name on mission span")
	// The tracer's existing GibsonMissionID attribute is preserved alongside
	// the flat mission_id attribute so legacy dashboards continue working.
	assert.Equal(t, mission.ID.String(), missionAttrs[GibsonMissionID].AsString(), "GibsonMissionID preserved")

	// ------------------------------------------------------------------
	// Assert on the decision (GenAI) span.
	// ------------------------------------------------------------------
	decisionAttrs, ok := byName[SpanGenAIChat]
	require.True(t, ok, "decision span not present; got spans: %v", spanNames(spans))

	assert.Equal(t, "acme-corp", decisionAttrs[AttrTenantID].AsString(), "tenant_id on decision span")
	assert.Equal(t, "user-alice", decisionAttrs[AttrUserID].AsString(), "user_id on decision span")
	assert.Equal(t, "user-alice", decisionAttrs[AttrInitiatorUserID].AsString(), "initiator_user_id on decision span")
	assert.Equal(t, "user-bob", decisionAttrs[AttrExecutorUserID].AsString(), "executor_user_id on decision span")
	assert.Equal(t, "mission-42", decisionAttrs[AttrMissionID].AsString(), "mission_id on decision span")
	assert.Equal(t, "run-42-1", decisionAttrs[AttrRunID].AsString(), "run_id on decision span")
	assert.Equal(t, "triage-agent", decisionAttrs[AttrAgentID].AsString(), "agent_id on decision span")
	assert.Equal(t, "reasoner", decisionAttrs[AttrSlotName].AsString(), "slot_name on decision span")
	// GenAI attributes (model + provider) are written by LogDecision independently.
	assert.Equal(t, "claude-sonnet-4", decisionAttrs[GenAIRequestModel].AsString(), "gen_ai.request.model on decision span")
	assert.Equal(t, "anthropic", decisionAttrs[GenAISystem].AsString(), "gen_ai.system on decision span")
}

// TestOTelMissionTracer_UnknownUser_Fallback asserts that when the mission
// starts with no identity in context, spans still carry the "unknown"
// sentinel for user_id and tenant falls back to SystemTenant — no panic,
// no missing attributes.
func TestOTelMissionTracer_UnknownUser_Fallback(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	tracer := NewOTelMissionTracer(tp, sdkmetric.NewMeterProvider(), nil)
	require.NotNil(t, tracer)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "unknown-user-mission",
		Objective: "No identity in context",
		TargetRef: "_",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	_, missionSpan, err := tracer.StartMissionTrace(context.Background(), mission)
	require.NoError(t, err)
	missionSpan.span.End()

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	attrs := map[string]attribute.Value{}
	for _, a := range spans[0].Attributes {
		attrs[string(a.Key)] = a.Value
	}

	assert.Equal(t, auth.SystemTenantString, attrs[AttrTenantID].AsString(),
		"tenant_id falls back to SystemTenant on empty context")
	assert.Equal(t, unknownUserSentinel, attrs[AttrUserID].AsString(),
		"user_id falls back to 'unknown' on empty context")
	_, hasInitiator := attrs[AttrInitiatorUserID]
	assert.False(t, hasInitiator, "initiator_user_id should be absent when not set")
	_, hasExecutor := attrs[AttrExecutorUserID]
	assert.False(t, hasExecutor, "executor_user_id should be absent when not set")
}

func spanNames(spans tracetest.SpanStubs) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.Name)
	}
	return out
}
