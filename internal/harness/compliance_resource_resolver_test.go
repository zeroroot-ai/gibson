package harness

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/gibson/internal/types"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeGraphReader is a programmable GraphReader stub.
type fakeGraphReader struct {
	nodes []graphrag.GraphNode
	err   error
	calls int
}

func (f *fakeGraphReader) QueryNodes(ctx context.Context, query graphrag.NodeQuery) ([]graphrag.GraphNode, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.nodes, nil
}

func tenantCtx(t string) context.Context {
	return auth.ContextWithTenantString(context.Background(), t)
}

func TestResourceResolver_ToolCall_GraphHit(t *testing.T) {
	reader := &fakeGraphReader{
		nodes: []graphrag.GraphNode{{ID: types.ID("host-123"), Labels: []graphrag.NodeType{"host"}}},
	}
	r := NewResourceResolver(reader, nil)

	req := toolCallRequest{
		Name:    "nmap",
		Request: &graphragpb.Host{Hostname: strptr("example.com")},
	}
	res := r.Resolve(tenantCtx("tenant-a"), MethodCallToolProto, req)

	if res.ResourceType != "tool:nmap" {
		t.Errorf("ResourceType = %q; want tool:nmap", res.ResourceType)
	}
	if res.ResourceURI == "" {
		t.Errorf("ResourceURI should be populated for graph-hit path")
	}
	if res.ResourceNodeID != "host-123" {
		t.Errorf("ResourceNodeID = %q; want host-123", res.ResourceNodeID)
	}
}

func TestResourceResolver_ToolCall_GraphMiss(t *testing.T) {
	reader := &fakeGraphReader{nodes: nil}
	r := NewResourceResolver(reader, nil)

	req := toolCallRequest{
		Name:    "nmap",
		Request: &graphragpb.Host{Hostname: strptr("unknown.example.com")},
	}
	res := r.Resolve(tenantCtx("tenant-a"), MethodCallToolProto, req)

	if res.ResourceType != "tool:nmap" {
		t.Errorf("ResourceType = %q; want tool:nmap", res.ResourceType)
	}
	if res.ResourceURI != "unknown.example.com" {
		t.Errorf("ResourceURI = %q; want unknown.example.com", res.ResourceURI)
	}
	if res.ResourceNodeID != "" {
		t.Errorf("ResourceNodeID should be empty on miss, got %q", res.ResourceNodeID)
	}
}

func TestResourceResolver_ToolCall_LookupError(t *testing.T) {
	reader := &fakeGraphReader{err: errors.New("graph offline")}
	r := NewResourceResolver(reader, nil)

	req := toolCallRequest{
		Name:    "nmap",
		Request: &graphragpb.Host{Hostname: strptr("example.com")},
	}
	res := r.Resolve(tenantCtx("tenant-a"), MethodCallToolProto, req)

	// Error must not propagate — resolver returns URI-only and logs.
	if res.ResourceURI != "example.com" {
		t.Errorf("ResourceURI = %q; want example.com (error path should still stamp URI)", res.ResourceURI)
	}
	if res.ResourceNodeID != "" {
		t.Errorf("ResourceNodeID should be empty after lookup error")
	}
}

func TestResourceResolver_ToolCall_NoTenantFallsBackToSystem(t *testing.T) {
	// auth.TenantStringFromContext falls back to SystemTenant when no tenant is
	// explicit in context — lookup still proceeds, scoped to system.
	reader := &fakeGraphReader{nodes: nil}
	r := NewResourceResolver(reader, nil)

	req := toolCallRequest{
		Name:    "nmap",
		Request: &graphragpb.Host{Hostname: strptr("example.com")},
	}
	res := r.Resolve(context.Background(), MethodCallToolProto, req)

	if res.ResourceURI != "example.com" {
		t.Errorf("ResourceURI should still be stamped, got %q", res.ResourceURI)
	}
	if res.ResourceNodeID != "" {
		t.Errorf("ResourceNodeID should be empty on system-tenant miss")
	}
}

func TestResourceResolver_LLMCall_PreCall(t *testing.T) {
	// Pre-call: only the slot is known, so the resolver stamps a placeholder
	// that ResolveLLMResponse later refines.
	r := NewResourceResolver(nil, nil)
	res := r.Resolve(context.Background(), MethodComplete, LLMTarget{Slot: "primary"})
	if res.ResourceType != "llm:slot:primary" {
		t.Errorf("ResourceType = %q", res.ResourceType)
	}
	if res.ResourceURI != "primary" {
		t.Errorf("ResourceURI = %q", res.ResourceURI)
	}
}

func TestResourceResolver_LLMCall_PostCallRefinement(t *testing.T) {
	// Requirement 4.7: post-call refinement stamps resource_type = llm:{provider}
	// and resource_uri = model_id.
	r := NewResourceResolver(nil, nil)
	res := r.ResolveLLMResponse("anthropic", "claude-opus-4-6")
	if res.ResourceType != "llm:anthropic" {
		t.Errorf("ResourceType = %q; want llm:anthropic", res.ResourceType)
	}
	if res.ResourceURI != "claude-opus-4-6" {
		t.Errorf("ResourceURI = %q; want claude-opus-4-6", res.ResourceURI)
	}
	if res.ResourceNodeID != "" {
		t.Errorf("ResourceNodeID should be empty for LLM calls (Req 4.7)")
	}
}

func TestResourceResolver_LLMCall_LegacyStringRequest(t *testing.T) {
	// Back-compat path: bare slot string.
	r := NewResourceResolver(nil, nil)
	res := r.Resolve(context.Background(), MethodComplete, "primary")
	if res.ResourceType != "llm:slot:primary" {
		t.Errorf("ResourceType = %q", res.ResourceType)
	}
}

func TestResourceResolver_QueryPlugin(t *testing.T) {
	r := NewResourceResolver(nil, nil)
	res := r.Resolve(context.Background(), MethodQueryPlugin, "gitlab")
	if res.ResourceType != "plugin:gitlab" {
		t.Errorf("ResourceType = %q", res.ResourceType)
	}
}

func TestResourceResolver_QueryPlugin_WithMethod(t *testing.T) {
	r := NewResourceResolver(nil, nil)
	res := r.Resolve(context.Background(), MethodQueryPlugin, PluginTarget{Name: "gitlab", Method: "list_projects"})
	if res.ResourceType != "plugin:gitlab" {
		t.Errorf("ResourceType = %q", res.ResourceType)
	}
	if res.ResourceURI != "gitlab.list_projects" {
		t.Errorf("ResourceURI = %q; want gitlab.list_projects", res.ResourceURI)
	}
}

func TestResourceResolver_ToolCall_WithCategory(t *testing.T) {
	// Requirement 4.1: tool calls stamp resource_type as "discovery:{category}".
	reader := &fakeGraphReader{nodes: nil}
	r := NewResourceResolver(reader, nil)

	req := ToolCallTarget{
		Name:     "httpx",
		Category: "endpoint",
		Request:  &graphragpb.Endpoint{Url: "https://example.com/api"},
	}
	res := r.Resolve(tenantCtx("tenant-a"), MethodCallToolProto, req)

	if res.ResourceType != "discovery:endpoint" {
		t.Errorf("ResourceType = %q; want discovery:endpoint (Req 4.1)", res.ResourceType)
	}
	if res.ResourceURI != "https://example.com/api" {
		t.Errorf("ResourceURI = %q", res.ResourceURI)
	}
}

func TestResourceResolver_GraphRead_ByNodeID(t *testing.T) {
	// Requirement 4.6: QueryNodes by specific id stamps both node_id and uri.
	r := NewResourceResolver(nil, nil)
	res := r.Resolve(context.Background(), MethodGetFindings, GraphReadTarget{
		NodeType: "finding",
		NodeID:   "finding-abc",
	})
	if res.ResourceType != "finding" {
		t.Errorf("ResourceType = %q", res.ResourceType)
	}
	if res.ResourceNodeID != "finding-abc" {
		t.Errorf("ResourceNodeID = %q; want finding-abc", res.ResourceNodeID)
	}
	if res.ResourceURI != "finding-abc" {
		t.Errorf("ResourceURI = %q; want finding-abc", res.ResourceURI)
	}
}

func TestResourceResolver_GraphWrite_PostStore(t *testing.T) {
	// Requirement 4.5: StoreNode post-store stamps the returned node id.
	r := NewResourceResolver(nil, nil)
	node := graphrag.GraphNode{
		ID:     types.ID("host-new-123"),
		Labels: []graphrag.NodeType{"host"},
	}
	res := r.ResolveGraphWrite(node)
	if res.ResourceNodeID != "host-new-123" {
		t.Errorf("ResourceNodeID = %q; want host-new-123 (Req 4.5)", res.ResourceNodeID)
	}
	if res.ResourceURI != "host-new-123" {
		t.Errorf("ResourceURI = %q", res.ResourceURI)
	}
}

func TestResourceResolver_NilReader(t *testing.T) {
	// Nil reader is allowed — resolver must not panic and must still stamp URI.
	r := NewResourceResolver(nil, nil)
	req := toolCallRequest{
		Name:    "nmap",
		Request: &graphragpb.Host{Hostname: strptr("example.com")},
	}
	res := r.Resolve(tenantCtx("tenant-a"), MethodCallToolProto, req)
	if res.ResourceURI != "example.com" {
		t.Errorf("ResourceURI = %q", res.ResourceURI)
	}
}

func strptr(s string) *string { return &s }

// --------------------------------------------------------------------------
// Slot-binding lookup tests (Task 13)
// --------------------------------------------------------------------------

func TestResolveLLMCall_WithSlotBinding(t *testing.T) {
	r := &ResourceResolver{}

	bindings := map[string]SlotBinding{
		"primary": {Provider: "anthropic", ModelID: "claude-3-5-sonnet-20241022"},
	}
	ctx := ContextWithSlotBindings(context.Background(), bindings)

	target := LLMTarget{Slot: "primary", Ctx: ctx}
	res := r.resolveLLMCall(target)

	if res.ResourceType != "llm:anthropic" {
		t.Errorf("ResourceType = %q, want %q", res.ResourceType, "llm:anthropic")
	}
	if res.ResourceURI != "claude-3-5-sonnet-20241022" {
		t.Errorf("ResourceURI = %q, want %q", res.ResourceURI, "claude-3-5-sonnet-20241022")
	}
}

func TestResolveLLMCall_NoSlotBinding_FallsBackToSlotPlaceholder(t *testing.T) {
	r := &ResourceResolver{}

	// Context has no bindings.
	target := LLMTarget{Slot: "primary", Ctx: context.Background()}
	res := r.resolveLLMCall(target)

	if res.ResourceType != "llm:slot:primary" {
		t.Errorf("ResourceType = %q, want %q", res.ResourceType, "llm:slot:primary")
	}
	if res.ResourceURI != "primary" {
		t.Errorf("ResourceURI = %q, want %q", res.ResourceURI, "primary")
	}
}

func TestResolveLLMCall_ProviderAlreadySet_SkipsBindingLookup(t *testing.T) {
	r := &ResourceResolver{}

	// Provider and ModelID already populated — this is the post-call path.
	// Even if a binding exists for a different model, the explicit values win.
	bindings := map[string]SlotBinding{
		"primary": {Provider: "openai", ModelID: "gpt-4o"},
	}
	ctx := ContextWithSlotBindings(context.Background(), bindings)

	target := LLMTarget{
		Slot:     "primary",
		Provider: "anthropic",
		ModelID:  "claude-3-opus-20240229",
		Ctx:      ctx,
	}
	res := r.resolveLLMCall(target)

	if res.ResourceType != "llm:anthropic" {
		t.Errorf("ResourceType = %q, want %q", res.ResourceType, "llm:anthropic")
	}
	if res.ResourceURI != "claude-3-opus-20240229" {
		t.Errorf("ResourceURI = %q, want %q", res.ResourceURI, "claude-3-opus-20240229")
	}
}

func TestSlotBindingsFromContext_NilIfAbsent(t *testing.T) {
	bindings := SlotBindingsFromContext(context.Background())
	if bindings != nil {
		t.Errorf("expected nil bindings, got %v", bindings)
	}
}

func TestContextWithSlotBindings_RoundTrip(t *testing.T) {
	want := map[string]SlotBinding{
		"analysis": {Provider: "gemini", ModelID: "gemini-1.5-pro"},
	}
	ctx := ContextWithSlotBindings(context.Background(), want)
	got := SlotBindingsFromContext(ctx)
	if got["analysis"].Provider != "gemini" {
		t.Errorf("Provider = %q, want %q", got["analysis"].Provider, "gemini")
	}
}
