// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/schema"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// matchBlocked reports the first candidate tool id that appears in the
// mission-level deny list, matched case-insensitively. It is the single place
// blocked_tools is compared, so native and meta-tool paths agree.
func matchBlocked(blocked []string, candidates ...string) (string, bool) {
	if len(blocked) == 0 {
		return "", false
	}
	set := make(map[string]struct{}, len(blocked))
	for _, b := range blocked {
		if b = strings.ToLower(strings.TrimSpace(b)); b != "" {
			set[b] = struct{}{}
		}
	}
	for _, c := range candidates {
		if _, ok := set[strings.ToLower(strings.TrimSpace(c))]; ok {
			return c, true
		}
	}
	return "", false
}

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
				"canonical id, description, and input schema.",
			InputSchema: schema.Object(map[string]schema.JSON{
				"query":     schema.StringWithDesc("Free-text description of the capability you need (e.g. \"open a gitlab issue\")."),
				"sources":   schema.Array(schema.StringWithDesc("Restrict to a source: \"mcp\" or \"native\".")),
				"connector": schema.StringWithDesc("Restrict to a single connector/plugin name. Optional."),
				"limit":     schema.Int(),
			}),
		},
		{
			Name: metatool.InvokeToolName,
			Description: "Invoke a catalog tool by its canonical id (from search_tools), passing the " +
				"tool's arguments. The id has the form mcp:<connector>:<tool> or native:<tool>. Authorization is " +
				"enforced; only ids returned by search_tools are invocable.",
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

	h, err := s.getHarness(ctx, req.GetContext())
	if err != nil {
		return nil, err
	}

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
	if state.Status != "active" {
		// gibson:no-tool-executed — denied before dispatch.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "mission run is not active"), nil
	}

	authorizer := catalog.NewFGAAuthorizer(s.componentAuthorizer)
	handler := metatool.NewHandler(
		catalog.NewEngine(component.NewCatalogToolLister(s.componentRegistry, s.connectors), authorizer),
		authorizer,
		s.connectors,
	)
	caller := catalog.Caller{Subject: "user:" + state.UserID, Tenant: state.TenantID}

	switch req.GetName() {
	case metatool.SearchToolsName:
		return s.metaSearch(ctx, handler, caller, req.GetInputJson())
	case metatool.InvokeToolName:
		return s.metaInvoke(ctx, req.GetContext(), handler, h, caller, h.Mission().BlockedTools, req.GetInputJson())
	default:
		// gibson:no-tool-executed — not one of the two known meta-tools.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, "unknown meta-tool: "+req.GetName()), nil
	}
}

func (s *HarnessCallbackService) metaSearch(ctx context.Context, h *metatool.Handler, caller catalog.Caller, inputJSON []byte) (*harnesspb.CallToolProtoResponse, error) {
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
		}
		if len(c.InputSchema) > 0 {
			out.Candidates[i].InputSchema = json.RawMessage(c.InputSchema)
		}
	}
	// gibson:no-tool-executed — search_tools never invokes a tool; only
	// invoke_tool does, and that path records below.
	return marshalMetaResult(s, out)
}

func (s *HarnessCallbackService) metaInvoke(ctx context.Context, contextInfo *harnesspb.ContextInfo, h *metatool.Handler, harness AgentHarness, caller catalog.Caller, blocked []string, inputJSON []byte) (*harnesspb.CallToolProtoResponse, error) {
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

	// Mission-level blocked_tools denial, by canonical id. Checked here (before
	// authz and dispatch) so the deny is independent of the agent and fails
	// closed. Match both the id the agent supplied and its canonical form.
	canon := in.ID
	if tid, err := toolid.Parse(in.ID); err == nil {
		canon = tid.Canonical()
	}
	if blockedID, ok := matchBlocked(blocked, in.ID, canon); ok {
		// gibson:no-tool-executed — denied before dispatch.
		return metaToolErr(commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "tool '"+blockedID+"' is blocked by mission policy"), nil
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

	tid, err := h.Authorize(ctx, caller, in.ID)
	if err == nil && tid.Source == toolid.SourceNative {
		// The tool call handler owns a native call and its one record.
		return s.invokeNativeTool(ctx, contextInfo, harness, tid.Tool, canon, argsJSON)
	}
	var result any
	if err == nil {
		result, err = h.Dispatch(ctx, caller, tid, in.Args)
	}
	if err != nil {
		code := commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
		if errors.Is(err, metatool.ErrUnauthorized) {
			code = commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED
		}
		s.logger.WarnContext(ctx, "meta-tool invoke failed", "id", in.ID, "tenant", caller.Tenant, "err", err)

		// Flight recorder completeness (ADR-0131): invoke_tool dispatches a
		// real catalog tool through the same trust boundary as a native
		// CallToolProto call, so a failed invocation must be recorded too —
		// exactly like captureToolCall's contract for the native path.
		s.captureToolCall(ctx, contextInfo, canon, string(argsJSON), "", err.Error())

		return metaToolErr(code, err.Error()), nil
	}

	resultJSON, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		// A tool result that cannot be marshaled to JSON is still a real,
		// completed invocation — the flight recorder must know it happened
		// even though there is no usable result payload to attach.
		s.logger.WarnContext(ctx, "meta-tool invoke result not JSON-marshalable", "id", in.ID, "tenant", caller.Tenant, "err", marshalErr)
		resultJSON = nil
	}

	// Flight recorder completeness (ADR-0131): invoke_tool is the
	// metatool dispatch path the completeness guard requires — the agent
	// never gets a real tool's result without an independent record of it.
	s.captureToolCall(ctx, contextInfo, canon, string(argsJSON), string(resultJSON), "")

	return marshalMetaResult(s, struct {
		Result any `json:"result"`
	}{Result: result})
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
		s.captureToolCall(ctx, contextInfo, canon, string(argsJSON), "", err.Error())
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
		return metaToolErr(e.GetCode(), e.GetMessage()), nil
	}
	return marshalMetaResult(s, struct {
		Result json.RawMessage `json:"result"`
	}{Result: json.RawMessage(resp.GetOutputJson())})
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
