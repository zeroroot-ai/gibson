// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/schema"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/sdk/auth"
)

// metaToolsWired reports whether the connector catalog is fully wired on this
// daemon. The two meta-tools are advertised and served only when it is, so a
// daemon without the catalog behaves exactly as before.
func (s *HarnessCallbackService) metaToolsWired() bool {
	return s.componentRegistry != nil && s.componentAuthorizer != nil && s.authzStore != nil
}

// metaToolDescriptors returns the two synthetic tools (ADR-0065) that
// the harness presents to the LLM in place of the full connector surface:
// search_tools for discovery and invoke_tool for invocation by canonical id.
func metaToolDescriptors() []ToolDescriptor {
	return []ToolDescriptor{
		{
			Name: metatool.SearchToolsName,
			Description: "Search the connector tool catalog for tools relevant to a task and " +
				"return a small, authorized, ranked set of candidates. Use this to discover " +
				"which tools exist before calling invoke_tool. Returns each candidate's " +
				"canonical id, description, and input schema. A result can also be an Agent Skill, " +
				"a method that you load with invoke_tool. Its id has the form skill:<name>.",
			InputSchema: schema.Object(map[string]schema.JSON{
				"query":     schema.StringWithDesc("Free-text description of the capability you need (e.g. \"open a gitlab issue\")."),
				"sources":   schema.Array(schema.StringWithDesc("Restrict to a source: \"mcp\", \"native\" or \"skill\".")),
				"connector": schema.StringWithDesc("Restrict to a single connector/plugin name. Optional."),
				"limit":     schema.Int(),
			}),
		},
		{
			Name: metatool.InvokeToolName,
			Description: "Invoke a catalog tool by its canonical id (from search_tools), passing the " +
				"tool's arguments. The id has the form mcp:<connector>:<tool>, native:<tool> or skill:<name>. " +
				"Authorization is " +
				"enforced; only ids returned by search_tools are invocable. A skill:<name> id returns the " +
				"body of an Agent Skill. Set args.file to a path from the file list to read one reference file.",
			InputSchema: schema.Object(map[string]schema.JSON{
				"id":   schema.StringWithDesc("Canonical tool id, e.g. mcp:gitlab:create_issue."),
				"args": schema.Any(),
			}, "id"),
		},
	}
}

// isMetaTool reports whether name is one of the reserved meta-tool names.
func isMetaTool(name string) bool {
	return name == metatool.SearchToolsName || name == metatool.InvokeToolName
}

// callMetaTool serves the two meta-tools from CallToolProto. It establishes the
// caller (user + tenant) from the run's authz state — exactly as the Authorize
// and SearchTools handlers do — builds the catalog engine + authorizer, and
// dispatches through metatool.Handler. invoke_tool re-checks can_execute there,
// because this in-process path does not pass the per-plugin ext-authz gate.
// A native:<tool> id then goes through the direct tool call handler, so it
// takes the sandbox path or the work queue path like a direct call (ADR-0065).
func (s *HarnessCallbackService) callMetaTool(ctx context.Context, req *harnesspb.CallToolProtoRequest) (*harnesspb.CallToolProtoResponse, error) {
	if !s.metaToolsWired() {
		// gibson:no-tool-executed — the catalog is not wired; nothing runs.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INTERNAL, "meta-tools are not wired on this daemon"), nil
	}

	// A bank member has no mission run and no run authz state. Its loop grant
	// is its authority (gibson#1612).
	member, isMember, merr := s.memberOfCall(ctx)
	if merr != nil {
		s.logger.ErrorContext(ctx, "meta-tool: the calling member could not be resolved", "err", merr)
		// gibson:no-tool-executed — an unresolved caller is refused, not read as no member.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the calling member could not be resolved"), nil
	}
	if isMember {
		return s.serveMemberMetaTool(ctx, req, member)
	}

	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}
	return s.serveMetaTool(ctx, req, h)
}

// metaHandler builds the handler of the two meta-tools over the catalog of the
// daemon. A mission run and a bank member use the same one.
func (s *HarnessCallbackService) metaHandler(req *harnesspb.CallToolProtoRequest) *metatool.Handler {
	authorizer := catalog.NewFGAAuthorizer(s.componentAuthorizer)
	handler := metatool.NewHandler(
		catalog.NewEngine(s.toolLister(component.NewCatalogToolLister(s.componentRegistry, s.connectors)), authorizer),
		authorizer,
		s.connectors,
	)
	handler.WithApprovalGate(s.toolApproval).WithGrantLookup(s.connectorGrants)
	if store := s.agentSkillStore(); store != nil {
		handler.WithSkills(store, s.skillLoadHook(req.GetContext()))
	}
	return handler
}

// memberCaller is the caller of a member for the can_execute check. The member
// has no person behind it, so the subject is the member set of the tenant, as it
// is for the daemon (TenantGrantSubject). The enable posture of the tenant
// grants can_execute on a connector to that set, so the tenant switch of a
// connector stops the member. The loop grant is a second check beside it.
func memberCaller(m memberCall) catalog.Caller {
	return catalog.Caller{Subject: TenantGrantSubject(m.tenant), Tenant: m.tenant, Mission: m.bankID}
}

// serveMemberMetaTool serves a meta-tool for a bank member. search_tools lists
// only the connector tools whose class the loop grant holds. invoke_tool runs
// the one connector call path with the loop check in front of can_execute. A
// member with no loop grant gets a refusal, and a refused invoke is recorded.
func (s *HarnessCallbackService) serveMemberMetaTool(ctx context.Context, req *harnesspb.CallToolProtoRequest, m memberCall) (*harnesspb.CallToolProtoResponse, error) {
	// A member owns its bank, its run and its agent, and nothing else. A request
	// that names another mission is refused before any lookup.
	if !m.ownsContext(req.GetContext()) {
		// gibson:no-tool-executed — the member names a mission that it does not own.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "a member call names a mission that the member does not own"), nil
	}
	// The rest of the path reads the verified context, never the request.
	req = &harnesspb.CallToolProtoRequest{Context: m.contextInfo(), Name: req.GetName(), InputJson: req.GetInputJson()}
	handler := s.metaHandler(req)
	caller := memberCaller(m)
	switch req.GetName() {
	case metatool.SearchToolsName:
		g, err := s.loopGrant(ctx, m)
		if err != nil {
			// gibson:no-tool-executed — search_tools never invokes a tool.
			return s.memberGrantRefusal(ctx, err), nil
		}
		return s.metaSearch(ctx, handler, caller, memberHidden(g), req.GetInputJson())
	case metatool.InvokeToolName:
		return s.metaInvoke(ctx, req.GetContext(), handler, nil, caller, metatool.MissionPolicy{}, req.GetInputJson(), &m)
	default:
		// gibson:no-tool-executed — not one of the two known meta-tools.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "unknown meta-tool: "+req.GetName()), nil
	}
}

// memberGrantRefusal maps a failed read of the loop grant to the reply.
func (s *HarnessCallbackService) memberGrantRefusal(ctx context.Context, err error) *harnesspb.CallToolProtoResponse {
	if errors.Is(err, ErrNoLoopGrant) {
		// gibson:no-tool-executed — no loop grant, so nothing ran.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "this member holds no loop grant")
	}
	s.logger.ErrorContext(ctx, "meta-tool: the loop grant could not be read", "err", err)
	// gibson:no-tool-executed — the grant is unread, so nothing ran.
	return metaToolErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the loop grant could not be read")
}

// memberHidden hides each tool that the loop grant does not cover. A skill and
// a native tool are hidden, because a loop grant covers connector tools only.
func memberHidden(g *LoopGrant) func(toolid.ID) bool {
	return func(id toolid.ID) bool {
		return id.Source != toolid.SourceMCP || !g.covers(connectorToolClass(id.Connector))
	}
}

// CallMetaTool serves a meta-tool for an agent in pull mode, which reaches the
// daemon through ComponentService.CallTool. The agent has no harness here, so
// an invoke_tool of a native id is refused: the agent calls a native tool by
// its own name. The run must belong to the tenant.
func (s *HarnessCallbackService) CallMetaTool(
	ctx context.Context, tenant, missionID, runID, name string, input []byte,
) (*harnesspb.CallToolProtoResponse, error) {
	if !s.metaToolsWired() {
		// gibson:no-tool-executed — the catalog is not wired; nothing runs.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INTERNAL, "meta-tools are not wired on this daemon"), nil
	}
	if runID == "" {
		// gibson:no-tool-executed — rejected before any dispatch is attempted.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "a meta-tool call needs the work item of a mission run"), nil
	}
	state, err := s.authzStore.Get(ctx, runID)
	if err != nil || state.TenantID != tenant {
		// gibson:no-tool-executed — no resolvable run state of this tenant.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "run authz state not found"), nil //nolint:nilerr // the denial is the response
	}
	return s.serveMetaTool(ctx, &harnesspb.CallToolProtoRequest{
		Context:   &harnesspb.ContextInfo{MissionId: missionID, MissionRunId: runID},
		Name:      name,
		InputJson: input,
	}, nil)
}

// serveMetaTool runs a meta-tool. The harness is nil for an agent in pull mode.
func (s *HarnessCallbackService) serveMetaTool(ctx context.Context, req *harnesspb.CallToolProtoRequest, h AgentHarness) (*harnesspb.CallToolProtoResponse, error) {
	runID := req.GetContext().GetMissionRunId()
	if runID == "" {
		runID = req.GetContext().GetAgentRunId()
	}
	if runID == "" {
		// gibson:no-tool-executed — rejected before any dispatch is attempted.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "meta-tool call requires a mission_run_id or agent_run_id"), nil
	}
	state, err := s.authzStore.Get(ctx, runID)
	if err != nil {
		s.logger.WarnContext(ctx, "meta-tool: run authz state not found", "run_id", runID, "err", err)
		// gibson:no-tool-executed — no resolvable run state, so nothing ran.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "run authz state not found"), nil
	}
	policy, err := s.policyFromState(ctx, state)
	if err != nil {
		s.logger.ErrorContext(ctx, "meta-tool: the mission policy could not be loaded", "run_id", runID, "err", err)
		// gibson:no-tool-executed — no policy, so nothing ran.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the mission policy could not be loaded"), nil
	}

	handler := s.metaHandler(req)
	caller := catalogCaller(ctx, state)

	switch req.GetName() {
	case metatool.SearchToolsName:
		if err := policy.CheckRun(ctx); err != nil {
			// gibson:no-tool-executed — denied before the search.
			return metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "mission run is not active"), nil //nolint:nilerr // the denial is the response, not a transport error
		}
		return s.metaSearch(ctx, handler, caller, hideBlockedSkills(policy.Blocked), req.GetInputJson())
	case metatool.InvokeToolName:
		return s.metaInvoke(ctx, req.GetContext(), handler, h, caller, policy, req.GetInputJson(), nil)
	default:
		// gibson:no-tool-executed — not one of the two known meta-tools.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "unknown meta-tool: "+req.GetName()), nil
	}
}

func (s *HarnessCallbackService) metaSearch(ctx context.Context, h *metatool.Handler, caller catalog.Caller, hide func(toolid.ID) bool, inputJSON []byte) (*harnesspb.CallToolProtoResponse, error) {
	var in struct {
		Query     string   `json:"query"`
		Sources   []string `json:"sources"`
		Connector string   `json:"connector"`
		Limit     int      `json:"limit"`
	}
	if len(inputJSON) > 0 {
		if err := json.Unmarshal(inputJSON, &in); err != nil {
			// gibson:no-tool-executed — malformed request, nothing dispatched.
			return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "search_tools input is not valid JSON: "+err.Error()), nil
		}
	}

	candidates, err := h.Search(ctx, caller, catalog.Query{
		Text:      in.Query,
		Sources:   toToolSources(in.Sources),
		Connector: in.Connector,
		Limit:     in.Limit,
		Hide:      hide,
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "meta-tool search failed", "tenant", caller.Tenant, "err", err)
		// gibson:no-tool-executed — search_tools only queries the catalog; it
		// never invokes a tool, so a search failure has nothing to record.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INTERNAL, "tool search failed"), nil
	}

	out := struct {
		Candidates []metaSearchCandidate `json:"candidates"`
	}{Candidates: make([]metaSearchCandidate, len(candidates))}
	for i, c := range candidates {
		out.Candidates[i] = metaSearchCandidate{
			ID:          c.ID,
			Source:      c.Source,
			Connector:   c.Connector,
			Tool:        c.Tool,
			Description: c.Description,
			ToolClass:   connectorToolClass(c.Connector),
		}
		if len(c.InputSchema) > 0 {
			out.Candidates[i].InputSchema = json.RawMessage(c.InputSchema)
		}
	}
	// gibson:no-tool-executed — search_tools never invokes a tool; only
	// invoke_tool does, and that path records below.
	return marshalMetaResult(s, out)
}

func (s *HarnessCallbackService) metaInvoke(ctx context.Context, contextInfo *harnesspb.ContextInfo, h *metatool.Handler, harness AgentHarness, caller catalog.Caller, policy metatool.MissionPolicy, inputJSON []byte, member *memberCall) (*harnesspb.CallToolProtoResponse, error) {
	var in struct {
		ID   string         `json:"id"`
		Args map[string]any `json:"args"`
	}
	if err := json.Unmarshal(inputJSON, &in); err != nil {
		// gibson:no-tool-executed — malformed request, nothing dispatched.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "invoke_tool input is not valid JSON: "+err.Error()), nil
	}
	if in.ID == "" {
		// gibson:no-tool-executed — no id to dispatch to.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "invoke_tool requires a non-empty id"), nil
	}

	// argsJSON is the agent's own "args" bytes, captured verbatim as evidence —
	// a second, narrower decode of the SAME already-validated inputJSON,
	// rather than a re-marshal of in.Args, so the recorded evidence is
	// exactly what the agent sent instead of a re-serialized copy.
	var rawArgs struct {
		Args json.RawMessage `json:"args"`
	}
	_ = json.Unmarshal(inputJSON, &rawArgs) // inputJSON already parsed successfully above
	argsJSON := []byte(rawArgs.Args)
	if len(argsJSON) == 0 {
		argsJSON = []byte("{}")
	}

	// callID is the id that the flight recorder gave to the invoked call. The
	// reply carries it as tool_call_id, so a finding can cite the call.
	var callID string

	// The one connector call: mission policy, can_execute, the intent record,
	// the dispatch, and the flight recorder and audit records of the result.
	call := metatool.Call{
		Caller:    caller,
		ID:        in.ID,
		Args:      in.Args,
		ArgsJSON:  argsJSON,
		Policy:    policy,
		MissionID: contextInfo.GetMissionId(),
		RunID:     callerRun(ctx, contextInfo),
		// Flight recorder completeness (ADR-0131): invoke_tool dispatches a
		// real catalog tool through the same trust boundary as a native
		// CallToolProto call, so each call is recorded, a failed one too.
		Recorder: func(rctx context.Context, rec metatool.CallRecord, resultJSON []byte, errText string) string {
			callID = s.captureGrantedToolCall(rctx, contextInfo, newToolCallID(contextInfo), rec.Canonical,
				string(rec.ArgsJSON), string(resultJSON), errText, rec.GrantID, string(rec.ErrCode))
			return callID
		},
		Observer: &harnessCallObserver{s: s},
	}
	if member != nil {
		// The call of a bank member: the loop grant is checked first, and the
		// record names the member.
		call.Loop = s.loopCheck(*member)
		call.MemberID = member.memberID
		call.RunID = member.runID
	}
	result, err := h.Call(ctx, call)
	switch {
	case err == nil:
		resp, merr := marshalMetaResult(s, struct {
			Result any `json:"result"`
		}{Result: result})
		return withToolCallID(resp, callID), merr
	case errors.Is(err, metatool.ErrNativeID):
		// The tool call handler owns a native call and its one record.
		if harness == nil {
			// gibson:no-tool-executed — a pull mode agent has no harness; it calls a native tool by name.
			return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, "call a native tool by its own name"), nil
		}
		tid, perr := toolid.Parse(in.ID)
		if perr != nil {
			tid, perr = toolid.Unflatten(in.ID)
		}
		if perr != nil {
			// gibson:no-tool-executed — the id was authorized, so it parses.
			return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT, perr.Error()), nil
		}
		return s.invokeNativeTool(ctx, contextInfo, harness, tid.Tool, tid.Canonical(), argsJSON)
	case errors.Is(err, metatool.ErrBlocked):
		// gibson:no-tool-executed — denied before dispatch.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, err.Error()), nil
	case errors.Is(err, metatool.ErrLoopGrantDenied):
		// gibson:no-tool-executed — the loop grant of the member does not cover the call.
		return withToolCallID(metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, err.Error()), callID), nil
	case errors.Is(err, metatool.ErrLoopGrantUnavailable):
		s.logger.ErrorContext(ctx, "meta-tool invoke refused: the loop grant could not be read", "id", in.ID, "tenant", caller.Tenant, "err", err)
		// gibson:no-tool-executed — an unread grant is not an empty one.
		return withToolCallID(metaToolErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the loop grant could not be read"), callID), nil
	case errors.Is(err, metatool.ErrRunInactive):
		// gibson:no-tool-executed — denied before dispatch.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "mission run is not active"), nil
	case errors.Is(err, metatool.ErrApprovalPending):
		// gibson:no-tool-executed — a person has not approved the call yet.
		return withToolCallID(metaToolErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
			err.Error()+". Do not retry now. Call again with the same arguments after the approval."), callID), nil
	case errors.Is(err, metatool.ErrMergeNotGranted):
		// gibson:no-tool-executed — the merge request has no merge slot yet.
		return withToolCallID(metaToolErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
			err.Error()+". Do not retry now. Call again after the merge slot is granted."), callID), nil
	case errors.Is(err, metatool.ErrApprovalDenied):
		// gibson:no-tool-executed — a person denied the call.
		return withToolCallID(metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, err.Error()), callID), nil
	case errors.Is(err, metatool.ErrApprovalUnavailable):
		// gibson:no-tool-executed — the tool needs approval and no queue exists.
		return withToolCallID(metaToolErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, err.Error()), callID), nil
	case errors.Is(err, metatool.ErrAuditUnavailable):
		s.logger.ErrorContext(ctx, "meta-tool invoke refused: the audit record could not be written", "id", in.ID, "tenant", caller.Tenant, "err", err)
		// gibson:no-tool-executed — no call happens without its record.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE, "the audit record of the call could not be written"), nil
	case errors.Is(err, metatool.ErrAuthzCheckFailed):
		// The check failed. It did not deny. The class and the fixed text are
		// the same as CallTool gives (metatool.ClassifyAuthzFailure). An outage
		// is UNAVAILABLE, so a member retries it. The cause goes to the log only.
		s.logger.WarnContext(ctx, "meta-tool invoke refused: the authorization check failed", "id", in.ID, "tenant", caller.Tenant, "err", err)
		// gibson:no-tool-executed — the check failed before any dispatch.
		return metaToolErr(authzFaultCode(err), authzFaultText(err)), nil
	}
	code := commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
	switch {
	case errors.Is(err, metatool.ErrUnauthorized):
		code = commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED
	case errors.Is(err, metatool.ErrConnectorTimeout):
		// Two sources: a connector that declared errorClasses set the class timeout, and it does
		// so only where a repeat is proven safe. The daemon also sets it when its own bound ends
		// the connect step, before any tool ran.
		code = commonpb.ErrorCode_ERROR_CODE_TIMEOUT
	case errors.Is(err, metatool.ErrConnectorRateLimited):
		// The vendor limits the rate. The member waits before it calls again.
		code = commonpb.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED
	case errors.Is(err, metatool.ErrConnectorUnavailable):
		// The call never reached the connector, or the connection broke. A later call may work.
		code = commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE
	}
	s.logger.WarnContext(ctx, "meta-tool invoke failed", "id", in.ID, "tenant", caller.Tenant, "err", err)
	// gibson:no-tool-executed — the observer recorded the failed call.
	return withToolCallID(metaToolErr(code, err.Error()), callID), nil
}

// runActiveCheck returns the run check of a mission policy for the status of a
// run in the authz store.
func runActiveCheck(status string) func(context.Context) error {
	return func(context.Context) error {
		if status != "active" {
			return fmt.Errorf("%w: status %q", metatool.ErrRunInactive, status)
		}
		return nil
	}
}

// MissionBlockedToolsSource reads the deny list of a mission from its stored
// definition. It reads the record of the tenant, not the memory of this replica.
type MissionBlockedToolsSource func(ctx context.Context, tenant, missionID string) ([]string, error)

// WithMissionBlockedTools wires the source of the mission deny list. A daemon
// with none refuses a connector call, because an unread deny list is not an
// empty one.
func WithMissionBlockedTools(src MissionBlockedToolsSource) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.missionBlockedTools = src
	}
}

// policyFromState builds the mission policy of the run in state: its active
// check from the run record, and its deny list from the stored definition of
// its mission. It fails when either cannot be read.
func (s *HarnessCallbackService) policyFromState(ctx context.Context, state *RunAuthzState) (metatool.MissionPolicy, error) {
	if s.missionBlockedTools == nil {
		return metatool.MissionPolicy{}, errors.New("the mission deny list source is not wired")
	}
	if state.MissionID == "" {
		return metatool.MissionPolicy{}, fmt.Errorf("run %q names no mission", state.RunID)
	}
	blocked, err := s.missionBlockedTools(ctx, state.TenantID, state.MissionID)
	if err != nil {
		return metatool.MissionPolicy{}, fmt.Errorf("read the deny list of mission %q: %w", state.MissionID, err)
	}
	return metatool.MissionPolicy{Blocked: blocked, RunActive: runActiveCheck(state.Status)}, nil
}

// storedBlockedTools reads the deny list of the mission of a callback from its
// stored definition. It is the one source of the deny list: the native tool
// path, the plugin path and invoke_tool all read it here. An unwired source and
// an unreadable list are errors, and the caller refuses the call.
func (s *HarnessCallbackService) storedBlockedTools(ctx context.Context, contextInfo *harnesspb.ContextInfo) ([]string, error) {
	if s.missionBlockedTools == nil {
		return nil, errors.New("the mission deny list source is not wired")
	}
	missionID := contextInfo.GetMissionId()
	if missionID == "" {
		return nil, errors.New("the callback names no mission")
	}
	blocked, err := s.missionBlockedTools(ctx, auth.TenantStringFromContext(ctx), missionID)
	if err != nil {
		return nil, fmt.Errorf("read the deny list of mission %q: %w", missionID, err)
	}
	return blocked, nil
}

// MissionPolicyForRun returns the mission policy of a run of the tenant, for a
// path that has no harness of its own, such as ComponentService.CallTool. A run
// of another tenant is refused.
func (s *HarnessCallbackService) MissionPolicyForRun(ctx context.Context, tenant, runID string) (metatool.MissionPolicy, error) {
	state, err := s.runStateFor(ctx, tenant, runID)
	if err != nil {
		return metatool.MissionPolicy{}, err
	}
	return s.policyFromState(ctx, state)
}

// runStateFor reads the authz state of a run and checks that the run belongs to
// the tenant. It is the one tenant check of a run (ADR-0027).
func (s *HarnessCallbackService) runStateFor(ctx context.Context, tenant, runID string) (*RunAuthzState, error) {
	if s.authzStore == nil {
		return nil, errors.New("the run authz store is not wired")
	}
	state, err := s.authzStore.Get(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("read the authz state of run %q: %w", runID, err)
	}
	if state.TenantID != tenant {
		return nil, fmt.Errorf("run %q does not belong to the tenant", runID)
	}
	return state, nil
}

// RecordToolCall writes the flight recorder record of a tool call that has no
// harness callback context, such as a connector call through
// ComponentService.CallTool. The tenant is on ctx.
func (s *HarnessCallbackService) RecordToolCall(ctx context.Context, rec metatool.CallRecord, resultJSON []byte, errText string) string {
	// The call has no harness callback context, so it is no turn of a job. It records no
	// task of a grant, also when ctx still holds the claims of a request that started the
	// mission of a tool node.
	return s.captureToolCallAs(ctx, "", &harnesspb.ContextInfo{MissionId: rec.MissionID, MissionRunId: rec.RunID, TaskId: rec.WorkID},
		uuid.NewString(), rec.Canonical, string(rec.ArgsJSON), string(resultJSON), errText, rec.GrantID, string(rec.ErrCode))
}

// TenantGrantSubject is the FGA subject of a connector call that the daemon
// makes for a tenant, with no agent behind it. It is the member set of the
// tenant: the subject that the tenant enable posture grants can_execute on a
// connector (catalogEnablePosture). A tenant kill switch on the connector
// therefore also stops the call of the daemon.
func TenantGrantSubject(tenant string) string { return "tenant:" + tenant + "#member" }

// CallConnectorForTenant runs one connector call that the daemon makes for a
// tenant, such as the revert of a fix after a failed health signal
// (gibson#1465). It takes the one path of every connector call,
// metatool.Handler.Call: the can_execute check of the tenant grant on the
// connector, the merge slot and approval marks of the manifest, the intent and
// result audit records, and the flight recorder record with the mission of the
// fix. The audit records name TenantGrantSubject as the actor.
func (s *HarnessCallbackService) CallConnectorForTenant(
	ctx context.Context, tenant, missionID, connector, tool string, args map[string]any,
) (any, error) {
	return s.callConnectorAs(ctx, connectorCallAs{
		tenant: tenant, missionID: missionID, connector: connector, tool: tool, args: args, daemon: true,
	})
}

// CallConnectorForMission runs the connector call of a TOOL node of a mission
// (gibson#1469). It takes the same path as CallConnectorForTenant and
// invoke_tool, metatool.Handler.Call, so a node gets the same can_execute check,
// the tenant kill switch, the approval mark, the audit records and the flight
// recorder as an agent does. The records name the work item of the node.
//
// The subject of the can_execute check is TenantGrantSubject, the member set of
// the tenant. That set holds can_execute on a connector only while the tenant
// has the connector enabled (catalogEnablePosture), so a connector that the
// tenant did not enable, or that its kill switch stops, is refused. The call is
// not a call of the daemon, and the handler refuses a tool with the role merge
// or daemon for a node. The mission policy of the run applies: the deny list of
// the stored definition and the state of the run. The run must belong to the
// tenant and to the mission of the node. A policy that cannot be read refuses
// the call.
func (s *HarnessCallbackService) CallConnectorForMission(
	ctx context.Context, tenant, missionID, runID, workID, connector, tool string, args map[string]any,
) (any, error) {
	if runID == "" {
		return nil, errors.New("a connector call of a mission node needs the run of the mission")
	}
	state, err := s.runStateFor(ctx, tenant, runID)
	if err != nil {
		return nil, err
	}
	if state.MissionID != missionID {
		return nil, fmt.Errorf("run %q does not belong to the mission of the node", runID)
	}
	policy, err := s.policyFromState(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("the mission policy of run %q: %w", runID, err)
	}
	return s.callConnectorAs(ctx, connectorCallAs{
		tenant: tenant, missionID: missionID, runID: runID, workID: workID, connector: connector, tool: tool,
		args: args, policy: policy, node: true,
	})
}

type connectorCallAs struct {
	tenant, missionID, runID, workID, connector, tool string
	args                                              map[string]any
	policy                                            metatool.MissionPolicy
	daemon, node                                      bool
}

// callConnectorAs is the one function behind the two calls above.
func (s *HarnessCallbackService) callConnectorAs(ctx context.Context, c connectorCallAs) (any, error) {
	if c.tenant == "" || c.connector == "" || c.tool == "" {
		return nil, errors.New("a connector call of the daemon needs a tenant, a connector and a tool")
	}
	if s.connectors == nil || s.componentAuthorizer == nil {
		return nil, errors.New("the connector client or the authorizer is not wired")
	}
	tid := toolid.ID{Source: toolid.SourceMCP, Connector: c.connector, Tool: c.tool}
	subject := TenantGrantSubject(c.tenant)
	tenantID, err := auth.NewTenantID(c.tenant)
	if err != nil {
		return nil, fmt.Errorf("connector call for tenant %q: %w", c.tenant, err)
	}
	ctx = auth.ContextWithTenantString(ctx, c.tenant)
	ctx = auth.WithIdentity(ctx, auth.Identity{Subject: subject, Tenant: tenantID, CredentialType: auth.CredentialOIDCUser})

	authorizer := catalog.NewFGAAuthorizer(s.componentAuthorizer)
	handler := metatool.NewHandler(nil, authorizer, s.connectors).WithApprovalGate(s.toolApproval)
	result, err := handler.Call(ctx, metatool.Call{
		Caller:    catalog.Caller{Subject: subject, Tenant: c.tenant, Mission: c.missionID},
		ID:        tid.Canonical(),
		Args:      c.args,
		Policy:    c.policy,
		MissionID: c.missionID,
		RunID:     c.runID,
		WorkID:    c.workID,
		Node:      c.node,
		Recorder:  s.RecordToolCall,
		Observer:  &harnessCallObserver{s: s},
		Daemon:    c.daemon,
	})
	if err != nil {
		return nil, fmt.Errorf("connector call %s for tenant %q: %w", tid.Canonical(), c.tenant, err)
	}
	return result, nil
}

// harnessCallObserver writes the intent and result audit records of an
// invoke_tool call of the harness.
type harnessCallObserver struct {
	s *HarnessCallbackService
}

var _ metatool.CallObserver = (*harnessCallObserver)(nil)

// auditCtx gives the audit logger an actor. A call from the callback listener
// carries no identity of its own, so the user of the run is the actor then.
func auditCtx(ctx context.Context, rec metatool.CallRecord) context.Context {
	if id, err := auth.IdentityFromContext(ctx); err == nil && id.Subject != "" {
		return ctx
	}
	tid, err := auth.NewTenantID(rec.Tenant)
	if err != nil {
		return ctx
	}
	return auth.WithIdentity(ctx, auth.Identity{Subject: rec.Subject, Tenant: tid, CredentialType: auth.CredentialOIDCUser})
}

func (o *harnessCallObserver) Intent(ctx context.Context, rec metatool.CallRecord) error {
	if err := (metatool.AuditRecorder{Log: o.s.connectorAudit}).Intent(auditCtx(ctx, rec), rec); err != nil {
		return fmt.Errorf("audit intent of %s: %w", rec.Canonical, err)
	}
	return nil
}

func (o *harnessCallObserver) Result(ctx context.Context, rec metatool.CallRecord, _ []byte, callErr error) {
	if rec.Connector == "" {
		return
	}
	if err := (metatool.AuditRecorder{Log: o.s.connectorAudit}).Result(auditCtx(ctx, rec), rec, callErr); err != nil {
		o.s.logger.ErrorContext(ctx, "meta-tool invoke: the result audit record was not written", "tenant", rec.Tenant, "err", err)
	}
}

// invokeNativeTool sends an authorized native:<tool> id from invoke_tool to
// the tool call handler of this service. That handler owns the whole call:
// the mission deny list, the execute gate of the dispatch, the sandbox path
// or the work queue path, the discovery ingest and the one record of the
// call. A tool with no usable descriptor never reaches it, and this function
// records that refusal.
func (s *HarnessCallbackService) invokeNativeTool(ctx context.Context, contextInfo *harnesspb.ContextInfo, harness AgentHarness, tool, canon string, argsJSON []byte) (*harnesspb.CallToolProtoResponse, error) {
	desc, err := harness.GetToolDescriptor(ctx, tool)
	if err == nil && (desc.InputProtoType == "" || desc.OutputProtoType == "") {
		err = fmt.Errorf("native tool %q declares no input or output message type", tool)
	}
	if err != nil {
		s.captureToolCall(ctx, contextInfo, newToolCallID(contextInfo), canon, string(argsJSON), "", err.Error())
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, fmt.Sprintf("native tool %q: %v", tool, err)), nil
	}

	resp, err := s.CallToolProto(ctx, &harnesspb.CallToolProtoRequest{
		Context:    contextInfo,
		Name:       tool,
		InputType:  desc.InputProtoType,
		OutputType: desc.OutputProtoType,
		InputJson:  argsJSON,
	})
	if err != nil {
		return nil, err
	}
	if e := resp.GetError(); e != nil {
		return withToolCallID(metaToolErr(e.GetCode(), e.GetMessage()), resp.GetToolCallId()), nil
	}
	out, merr := marshalMetaResult(s, struct {
		Result json.RawMessage `json:"result"`
	}{Result: json.RawMessage(resp.GetOutputJson())})
	return withToolCallID(out, resp.GetToolCallId()), merr
}

// metaSearchCandidate is the LLM-facing shape of a catalog candidate. InputSchema
// is embedded raw so the agent sees the tool's own JSON schema verbatim.
type metaSearchCandidate struct {
	ID          string          `json:"id"`
	Source      string          `json:"source,omitempty"`
	Connector   string          `json:"connector,omitempty"`
	Tool        string          `json:"tool,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	// ToolClass is the tool class of the connector of the tool (ADR-0177), for
	// example scanner or siem. It is empty for a tool that no catalog
	// connector serves.
	ToolClass string `json:"tool_class,omitempty"`
}

// connectorToolClass returns the tool class that the catalog states for the
// connector, or "" when the catalog does not list it.
func connectorToolClass(connector string) string {
	if connector == "" {
		return ""
	}
	e, err := componentcatalog.LookupConnector(connector)
	if err != nil {
		return ""
	}
	return e.Class
}

func marshalMetaResult(s *HarnessCallbackService, v any) (*harnesspb.CallToolProtoResponse, error) {
	b, err := json.Marshal(v)
	if err != nil {
		s.logger.Error("meta-tool: failed to marshal result", "err", err)
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_INTERNAL, "failed to marshal meta-tool result"), nil
	}
	return &harnesspb.CallToolProtoResponse{OutputJson: b}, nil
}

func metaToolErr(code commonpb.ErrorCode, msg string) *harnesspb.CallToolProtoResponse {
	return &harnesspb.CallToolProtoResponse{
		Error: &harnesspb.HarnessError{Code: code, Message: msg},
	}
}

// withToolCallID sets tool_call_id on a reply and returns the reply. A nil reply
// stays nil.
func withToolCallID(resp *harnesspb.CallToolProtoResponse, id string) *harnesspb.CallToolProtoResponse {
	if resp != nil {
		resp.ToolCallId = id
	}
	return resp
}

// authzFaultCode is the error code of a failed authorization check on the
// invoke_tool path.
func authzFaultCode(err error) commonpb.ErrorCode {
	fault, _ := metatool.ClassifyAuthzFailure(err)
	switch fault {
	case metatool.AuthzFaultTimeout:
		return commonpb.ErrorCode_ERROR_CODE_TIMEOUT
	case metatool.AuthzFaultUnavailable:
		return commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE
	default:
		return commonpb.ErrorCode_ERROR_CODE_INTERNAL
	}
}

// authzFaultText is the fixed text of a failed authorization check.
func authzFaultText(err error) string {
	_, msg := metatool.ClassifyAuthzFailure(err)
	return msg
}
