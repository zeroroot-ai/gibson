package harness

import (
	"context"
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/component"
)

// Embed the full interfaces and override only the one method the handler uses,
// so the fakes stay tiny.

type fakeSearchReg struct {
	component.ComponentRegistry
	comps []component.ComponentInfo
}

func (f fakeSearchReg) ListTenantComponents(context.Context, string) ([]component.ComponentInfo, error) {
	return f.comps, nil
}

type fakeSearchAuthz struct {
	authz.Authorizer
	allow    map[string]bool
	lastUser string
}

func (f *fakeSearchAuthz) Check(_ context.Context, user, _, object string) (bool, error) {
	f.lastUser = user
	return f.allow[object], nil
}

type fakeSearchAuthzStore struct{ state *RunAuthzState }

func (f fakeSearchAuthzStore) Get(context.Context, string) (*RunAuthzState, error) {
	return f.state, nil
}

// End to end: caller subject is user:<run user>, the per-tool gate is can_invoke
// on the tenant-qualified plugin object, and the response carries the canonical
// id + description.
func TestSearchTools_FiltersByCanInvokeAndMaps(t *testing.T) {
	authzer := &fakeSearchAuthz{allow: map[string]bool{
		"plugin:acme:gitlab": true,  // allowed
		"plugin:acme:github": false, // denied
	}}
	svc := &HarnessCallbackService{
		logger:     slog.Default(),
		authzStore: fakeSearchAuthzStore{state: &RunAuthzState{UserID: "alice", TenantID: "acme", Status: "active"}},
		componentRegistry: fakeSearchReg{comps: []component.ComponentInfo{
			{Kind: "plugin", Name: "gitlab", Methods: []component.MethodInfo{{Name: "create_issue", Description: "open a gitlab issue"}}},
			{Kind: "plugin", Name: "github", Methods: []component.MethodInfo{{Name: "create_issue", Description: "open a github issue"}}},
		}},
		componentAuthorizer: authzer,
	}

	resp, err := svc.SearchTools(context.Background(), &harnesspb.SearchToolsRequest{
		Context: &harnesspb.ContextInfo{MissionRunId: "run-1"},
	})
	if err != nil {
		t.Fatalf("SearchTools error: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("unexpected response error: %v", resp.GetError())
	}
	if len(resp.Candidates) != 1 {
		t.Fatalf("got %d candidates, want 1 (github denied): %+v", len(resp.Candidates), resp.Candidates)
	}
	c := resp.Candidates[0]
	if c.GetId() != "mcp:gitlab:create_issue" || c.GetDescription() != "open a gitlab issue" {
		t.Fatalf("candidate = %+v, want mcp:gitlab:create_issue / open a gitlab issue", c)
	}
	if authzer.lastUser != "user:alice" {
		t.Fatalf("caller subject = %q, want user:alice", authzer.lastUser)
	}
}

func TestSearchTools_UnavailableWhenNotWired(t *testing.T) {
	svc := &HarnessCallbackService{logger: slog.Default()}
	_, err := svc.SearchTools(context.Background(),
		&harnesspb.SearchToolsRequest{Context: &harnesspb.ContextInfo{MissionRunId: "run-1"}})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable when not wired, got %v", err)
	}
}

func TestSearchTools_RequiresRunID(t *testing.T) {
	svc := &HarnessCallbackService{
		logger:              slog.Default(),
		authzStore:          fakeSearchAuthzStore{state: &RunAuthzState{Status: "active"}},
		componentRegistry:   fakeSearchReg{},
		componentAuthorizer: &fakeSearchAuthz{},
	}
	_, err := svc.SearchTools(context.Background(),
		&harnesspb.SearchToolsRequest{Context: &harnesspb.ContextInfo{}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for missing run id, got %v", err)
	}
}
