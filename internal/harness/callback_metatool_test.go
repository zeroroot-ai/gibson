package harness

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"

	"github.com/zeroroot-ai/gibson/internal/catalog"
	"github.com/zeroroot-ai/gibson/internal/metatool"
	"github.com/zeroroot-ai/gibson/internal/toolid"
)

type mtSearcher struct {
	ret []catalog.Candidate
	err error
}

func (f mtSearcher) Search(context.Context, catalog.Caller, catalog.Query) ([]catalog.Candidate, error) {
	return f.ret, f.err
}

type mtAuthz struct{ allow map[string]bool }

func (f mtAuthz) CanExecute(_ context.Context, _ catalog.Caller, id toolid.ID) (bool, error) {
	return f.allow[id.Canonical()], nil
}

type mtQuerier struct {
	gotName, gotMethod string
	ret                any
}

func (f *mtQuerier) QueryPlugin(_ context.Context, name, method string, _ map[string]any) (any, error) {
	f.gotName, f.gotMethod = name, method
	return f.ret, nil
}

func newSvc() *HarnessCallbackService { return &HarnessCallbackService{logger: slog.Default()} }

// search_tools returns candidates with their canonical id and the tool's own
// input schema embedded verbatim (not re-encoded as a string).
func TestMetaSearch_MapsCandidatesAndEmbedsRawSchema(t *testing.T) {
	h := metatool.NewHandler(mtSearcher{ret: []catalog.Candidate{
		{ID: "mcp:gitlab:create_issue", Source: "mcp", Connector: "gitlab", Tool: "create_issue",
			Description: "open an issue", InputSchema: []byte(`{"type":"object","properties":{"title":{"type":"string"}}}`)},
	}}, mtAuthz{}, nil)

	resp, err := newSvc().metaSearch(context.Background(), h, catalog.Caller{Tenant: "acme"}, []byte(`{"query":"issue","limit":3}`))
	if err != nil {
		t.Fatalf("metaSearch: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("unexpected error response: %v", resp.GetError())
	}
	var out struct {
		Candidates []struct {
			ID          string          `json:"id"`
			InputSchema json.RawMessage `json:"input_schema"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(resp.GetOutputJson(), &out); err != nil {
		t.Fatalf("output not valid JSON: %v (%s)", err, resp.GetOutputJson())
	}
	if len(out.Candidates) != 1 || out.Candidates[0].ID != "mcp:gitlab:create_issue" {
		t.Fatalf("candidates wrong: %+v", out.Candidates)
	}
	var sch map[string]any
	if err := json.Unmarshal(out.Candidates[0].InputSchema, &sch); err != nil || sch["type"] != "object" {
		t.Fatalf("embedded input_schema not preserved: %s", out.Candidates[0].InputSchema)
	}
}

// invoke_tool dispatches the decoded id and wraps the result under "result".
func TestMetaInvoke_DispatchesAndWrapsResult(t *testing.T) {
	q := &mtQuerier{ret: map[string]any{"number": 7}}
	h := metatool.NewHandler(nil, mtAuthz{allow: map[string]bool{"mcp:gitlab:create_issue": true}}, q)

	resp, err := newSvc().metaInvoke(context.Background(), h, catalog.Caller{Tenant: "acme"}, nil,
		[]byte(`{"id":"mcp:gitlab:create_issue","args":{"title":"x"}}`))
	if err != nil {
		t.Fatalf("metaInvoke: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("unexpected error response: %v", resp.GetError())
	}
	if q.gotName != "gitlab" || q.gotMethod != "create_issue" {
		t.Fatalf("dispatched to %s.%s, want gitlab.create_issue", q.gotName, q.gotMethod)
	}
	var out struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(resp.GetOutputJson(), &out); err != nil || out.Result["number"].(float64) != 7 {
		t.Fatalf("result not wrapped: %s (%v)", resp.GetOutputJson(), err)
	}
}

// An unauthorized id is reported as PERMISSION_DENIED and never dispatched.
func TestMetaInvoke_UnauthorizedIsPermissionDenied(t *testing.T) {
	q := &mtQuerier{}
	h := metatool.NewHandler(nil, mtAuthz{allow: map[string]bool{}}, q)

	resp, err := newSvc().metaInvoke(context.Background(), h, catalog.Caller{Tenant: "acme"}, nil,
		[]byte(`{"id":"mcp:github:create_issue"}`))
	if err != nil {
		t.Fatalf("metaInvoke: %v", err)
	}
	if resp.GetError().GetCode() != commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED {
		t.Fatalf("want PERMISSION_DENIED, got %v", resp.GetError())
	}
	if q.gotName != "" {
		t.Fatal("unauthorized id must not dispatch")
	}
}

// A mission-level blocked_tools entry denies the connector tool by canonical id,
// before authz or dispatch — even though the caller would otherwise be allowed.
func TestMetaInvoke_BlockedByMissionPolicy(t *testing.T) {
	q := &mtQuerier{}
	h := metatool.NewHandler(nil, mtAuthz{allow: map[string]bool{"mcp:gitlab:create_issue": true}}, q)

	resp, err := newSvc().metaInvoke(context.Background(), h, catalog.Caller{Tenant: "acme"},
		[]string{"mcp:gitlab:create_issue"},
		[]byte(`{"id":"mcp:gitlab:create_issue","args":{"title":"x"}}`))
	if err != nil {
		t.Fatalf("metaInvoke: %v", err)
	}
	if resp.GetError().GetCode() != commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED {
		t.Fatalf("want PERMISSION_DENIED for blocked tool, got %v", resp.GetError())
	}
	if q.gotName != "" {
		t.Fatal("blocked tool must not dispatch")
	}
}

func TestMatchBlocked(t *testing.T) {
	blocked := []string{"mcp:gitlab:create_issue", "NMAP"}
	if id, ok := matchBlocked(blocked, "mcp:slack:post"); ok {
		t.Fatalf("unexpected match: %s", id)
	}
	if _, ok := matchBlocked(blocked, "mcp:gitlab:create_issue"); !ok {
		t.Fatal("should match exact canonical id")
	}
	if _, ok := matchBlocked(blocked, "native:nmap", "nmap"); !ok {
		t.Fatal("should match case-insensitively across candidates")
	}
	if _, ok := matchBlocked(nil, "anything"); ok {
		t.Fatal("empty blocklist must never match")
	}
}

func TestMetaInvoke_MissingIdIsInvalidArgument(t *testing.T) {
	h := metatool.NewHandler(nil, mtAuthz{}, &mtQuerier{})
	resp, err := newSvc().metaInvoke(context.Background(), h, catalog.Caller{}, nil, []byte(`{"args":{}}`))
	if err != nil {
		t.Fatalf("metaInvoke: %v", err)
	}
	if resp.GetError().GetCode() != commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
		t.Fatalf("want INVALID_ARGUMENT, got %v", resp.GetError())
	}
}

func TestMetaToolDescriptors_Shape(t *testing.T) {
	ds := metaToolDescriptors()
	if len(ds) != 2 {
		t.Fatalf("want 2 descriptors, got %d", len(ds))
	}
	byName := map[string]ToolDescriptor{ds[0].Name: ds[0], ds[1].Name: ds[1]}
	if _, ok := byName[metatool.SearchToolsName]; !ok {
		t.Fatal("missing search_tools descriptor")
	}
	inv, ok := byName[metatool.InvokeToolName]
	if !ok {
		t.Fatal("missing invoke_tool descriptor")
	}
	if len(inv.InputSchema.Required) != 1 || inv.InputSchema.Required[0] != "id" {
		t.Fatalf("invoke_tool must require id, got %+v", inv.InputSchema.Required)
	}
	if !isMetaTool(metatool.SearchToolsName) || isMetaTool("nmap") {
		t.Fatal("isMetaTool classification wrong")
	}
}
