package harness

// Compliance action and effect string constants.
//
// These match the closed vocabularies declared on the compliance_signal node
// type in core/sdk/taxonomy/core.yaml (action enum + effect enum). The values
// are strings rather than a generated Go enum because the taxonomy generator
// emits enums as free-form strings with CEL-validated vocabularies — see
// core/sdk/graphrag/validation/validators_generated.go.
//
// The middleware must use these constants (not raw string literals) so that a
// single search turns up every emission site and so typos fail at build time.
const (
	// --- Actions (compliance_signal.action) ---

	ActionToolCall         = "tool_call"
	ActionLLMCall          = "llm_call"
	ActionMemoryRead       = "memory_read"
	ActionMemoryWrite      = "memory_write"
	ActionGraphRead        = "graph_read"
	ActionGraphWrite       = "graph_write"
	ActionPluginQuery      = "plugin_query"
	ActionDelegate         = "delegate"
	ActionFindingSubmit    = "finding_submit"
	ActionAuthzDecision    = "authz_decision"
	ActionMissionLifecycle = "mission_lifecycle"

	// --- Effects (compliance_signal.effect) ---

	EffectRead    = "read"
	EffectWrite   = "write"
	EffectBoth    = "both"
	EffectExecute = "execute"
	EffectNone    = "none"

	// --- Decisions (compliance_signal.decision) ---

	DecisionAllow      = "allow"
	DecisionDeny       = "deny"
	DecisionNotChecked = "not_checked"
)

// HarnessMethod is the identity of a single method on the AgentHarness
// interface. These string constants are used as keys into the action table
// and in metric labels.
type HarnessMethod string

const (
	// LLM methods
	MethodComplete                       HarnessMethod = "Complete"
	MethodCompleteWithTools              HarnessMethod = "CompleteWithTools"
	MethodStream                         HarnessMethod = "Stream"
	MethodCompleteStructuredAny          HarnessMethod = "CompleteStructuredAny"
	MethodCompleteStructuredAnyWithUsage HarnessMethod = "CompleteStructuredAnyWithUsage"

	// Tool methods
	MethodCallToolProto          HarnessMethod = "CallToolProto"
	MethodCallToolProtoStream    HarnessMethod = "CallToolProtoStream"
	MethodListTools              HarnessMethod = "ListTools"
	MethodGetToolDescriptor      HarnessMethod = "GetToolDescriptor"
	MethodGetToolCapabilities    HarnessMethod = "GetToolCapabilities"
	MethodGetAllToolCapabilities HarnessMethod = "GetAllToolCapabilities"

	// Plugin methods
	MethodQueryPlugin HarnessMethod = "QueryPlugin"
	MethodListPlugins HarnessMethod = "ListPlugins"

	// Sub-agent methods
	MethodDelegateToAgent HarnessMethod = "DelegateToAgent"
	MethodListAgents      HarnessMethod = "ListAgents"

	// Findings methods
	MethodSubmitFinding          HarnessMethod = "SubmitFinding"
	MethodGetFindings            HarnessMethod = "GetFindings"
	MethodGetPreviousRunFindings HarnessMethod = "GetPreviousRunFindings"
	MethodGetAllRunFindings      HarnessMethod = "GetAllRunFindings"

	// Memory tier methods (keyed separately because the action/effect
	// classification differs by tier operation, not by the Memory() getter).
	MethodMemoryGet    HarnessMethod = "Memory.Get"
	MethodMemorySet    HarnessMethod = "Memory.Set"
	MethodMemoryDelete HarnessMethod = "Memory.Delete"
	MethodMemoryAccess HarnessMethod = "Memory"

	// Context / identity getters (no-op entries — pure getters that do not
	// emit signals, but we still record them in the table so the coverage
	// assertion over AgentHarness methods passes).
	MethodMissionID               HarnessMethod = "MissionID"
	MethodMission                 HarnessMethod = "Mission"
	MethodMissionExecutionContext HarnessMethod = "MissionExecutionContext"
	MethodGetMissionRunHistory    HarnessMethod = "GetMissionRunHistory"
	MethodTarget                  HarnessMethod = "Target"
	MethodCheckpoint              HarnessMethod = "Checkpoint"
	MethodWorkspace               HarnessMethod = "Workspace"
	MethodWorkspaces              HarnessMethod = "Workspaces"

	// Observability getters (pure, non-emitting).
	MethodTracer     HarnessMethod = "Tracer"
	MethodLogger     HarnessMethod = "Logger"
	MethodMetrics    HarnessMethod = "Metrics"
	MethodTokenUsage HarnessMethod = "TokenUsage"
)

// ActionEntry is the classification for a single harness method: what
// compliance action it represents and what the default I/O effect is.
//
// Emit indicates whether the middleware should synthesize a compliance signal
// for this method call. Pure getters (Memory, Logger, Tracer, etc.) have
// Emit=false; every method that does I/O or a privileged operation has
// Emit=true.
//
// The default effect can be refined at call-site (for example, CallToolProto
// may be classified as read/write/both depending on the tool's declared
// capability — that refinement happens in compliance_middleware.go).
type ActionEntry struct {
	Action        string
	DefaultEffect string
	Emit          bool
}

// ActionTable maps a HarnessMethod to its ActionEntry.
type ActionTable map[HarnessMethod]ActionEntry

// actionTable is the authoritative mapping from harness method to
// (action, default effect, emit). Every method on the AgentHarness interface
// must have an entry; the coverage test in compliance_action_table_test.go
// enforces this at build/test time via reflection.
var actionTable = ActionTable{
	// --- LLM: read-shaped (sends a prompt, receives a completion) ---
	MethodComplete:                       {Action: ActionLLMCall, DefaultEffect: EffectRead, Emit: true},
	MethodCompleteWithTools:              {Action: ActionLLMCall, DefaultEffect: EffectRead, Emit: true},
	MethodStream:                         {Action: ActionLLMCall, DefaultEffect: EffectRead, Emit: true},
	MethodCompleteStructuredAny:          {Action: ActionLLMCall, DefaultEffect: EffectRead, Emit: true},
	MethodCompleteStructuredAnyWithUsage: {Action: ActionLLMCall, DefaultEffect: EffectRead, Emit: true},

	// --- Tools: execute-shaped; per-tool refinement happens at call-site ---
	MethodCallToolProto:          {Action: ActionToolCall, DefaultEffect: EffectExecute, Emit: true},
	MethodCallToolProtoStream:    {Action: ActionToolCall, DefaultEffect: EffectExecute, Emit: true},
	MethodListTools:              {Action: ActionToolCall, DefaultEffect: EffectRead, Emit: false},
	MethodGetToolDescriptor:      {Action: ActionToolCall, DefaultEffect: EffectRead, Emit: false},
	MethodGetToolCapabilities:    {Action: ActionToolCall, DefaultEffect: EffectRead, Emit: false},
	MethodGetAllToolCapabilities: {Action: ActionToolCall, DefaultEffect: EffectRead, Emit: false},

	// --- Plugins: pessimistic default (plugin methods can do anything) ---
	MethodQueryPlugin: {Action: ActionPluginQuery, DefaultEffect: EffectBoth, Emit: true},
	MethodListPlugins: {Action: ActionPluginQuery, DefaultEffect: EffectRead, Emit: false},

	// --- Sub-agents: the delegation event itself; child emissions are separate ---
	MethodDelegateToAgent: {Action: ActionDelegate, DefaultEffect: EffectNone, Emit: true},
	MethodListAgents:      {Action: ActionDelegate, DefaultEffect: EffectRead, Emit: false},

	// --- Findings: writes land in graph; reads are cheap-but-emit-worthy ---
	MethodSubmitFinding:          {Action: ActionFindingSubmit, DefaultEffect: EffectWrite, Emit: true},
	MethodGetFindings:            {Action: ActionGraphRead, DefaultEffect: EffectRead, Emit: true},
	MethodGetPreviousRunFindings: {Action: ActionGraphRead, DefaultEffect: EffectRead, Emit: true},
	MethodGetAllRunFindings:      {Action: ActionGraphRead, DefaultEffect: EffectRead, Emit: true},

	// --- Memory tier ops ---
	MethodMemoryGet:    {Action: ActionMemoryRead, DefaultEffect: EffectRead, Emit: true},
	MethodMemorySet:    {Action: ActionMemoryWrite, DefaultEffect: EffectWrite, Emit: true},
	MethodMemoryDelete: {Action: ActionMemoryWrite, DefaultEffect: EffectWrite, Emit: true},
	// Memory() getter returns the store; the store itself is wrapped by
	// compliance_middleware.go so per-op signals emit at tier call time.
	MethodMemoryAccess: {Action: ActionMemoryRead, DefaultEffect: EffectNone, Emit: false},

	// --- Pure context/identity getters (no signal) ---
	MethodMissionID:               {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},
	MethodMission:                 {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},
	MethodMissionExecutionContext: {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},
	MethodGetMissionRunHistory:    {Action: ActionMissionLifecycle, DefaultEffect: EffectRead, Emit: false},
	MethodTarget:                  {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},
	MethodCheckpoint:              {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},
	// Workspace getters return the agent's workspace handle; pure non-emitting accessors.
	MethodWorkspace:               {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},
	MethodWorkspaces:              {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},

	// --- Observability getters (no signal) ---
	MethodTracer:     {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},
	MethodLogger:     {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},
	MethodMetrics:    {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},
	MethodTokenUsage: {Action: ActionMissionLifecycle, DefaultEffect: EffectNone, Emit: false},
}

// Lookup returns the ActionEntry for a HarnessMethod. The second return value
// is false when the method is not known to the table — which the coverage
// test ensures never happens for any real AgentHarness method.
func (t ActionTable) Lookup(m HarnessMethod) (ActionEntry, bool) {
	e, ok := t[m]
	return e, ok
}

// DefaultActionTable returns the package-level default action table used by
// the production ComplianceMiddleware. Tests may build their own table.
func DefaultActionTable() ActionTable {
	return actionTable
}
