// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/catalog"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
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
	allow map[string]bool
	// killed lists the objects whose tenant execute kill switch is on.
	killed     map[string]bool
	lastUser   string
	lastObject string
	// tenantUser is the user of the last check of a tenant tuple.
	tenantUser string
}

// Check answers can_execute and the other relations of a user from allow. For the
// member set of a tenant the catalog asks two tuples of the tenant instead:
// tenant_enabled, which follows allow, and tenant_execute_disabled, which follows
// killed (see catalog.FGAAuthorizer).
func (f *fakeSearchAuthz) Check(_ context.Context, user, relation, object string) (bool, error) {
	f.lastUser = user
	f.lastObject = object
	switch relation {
	case "tenant_enabled":
		f.tenantUser = user
		return f.allow[object], nil
	case "tenant_execute_disabled":
		f.tenantUser = user
		return f.killed[object], nil
	}
	return f.allow[object], nil
}

type fakeSearchAuthzStore struct{ state *RunAuthzState }

func (f fakeSearchAuthzStore) Get(context.Context, string) (*RunAuthzState, error) {
	return f.state, nil
}

// End to end: caller subject is user:<run user>, the per-tool gate is
// can_execute on the connector component (ADR-0067), and the response carries
// the canonical id + description.
func TestSearchTools_FiltersByCanInvokeAndMaps(t *testing.T) {
	authzer := &fakeSearchAuthz{allow: map[string]bool{
		"component:connector/gitlab": true,  // allowed
		"component:connector/github": false, // denied
	}}
	svc := &HarnessCallbackService{
		agentSkills: noAgentSkillStore, skillLoadSink: noSkillLoadSink,
		logger:     slog.Default(),
		authzStore: fakeSearchAuthzStore{state: &RunAuthzState{UserID: "alice", TenantID: "acme", Status: "active"}},
		componentRegistry: fakeSearchReg{comps: []component.ComponentInfo{
			// A plugin has no MCP (ADR-0065): its methods are not catalog
			// entries, even when a connector has the same name.
			{Kind: "plugin", Name: "gitlab", Methods: []component.MethodInfo{{Name: "create_issue", Description: "a plugin method"}}},
		}},
		connectors: fakeConnectors{tools: []catalog.ToolEntry{
			{Source: toolid.SourceMCP, Connector: "gitlab", Tool: "create_issue", Description: "open a gitlab issue"},
			{Source: toolid.SourceMCP, Connector: "github", Tool: "create_issue", Description: "open a github issue"},
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
	// The typed result carries the tool class of the connector (ADR-0177), as the
	// result of the search_tools meta tool does.
	if c.GetToolClass() != "git-host" {
		t.Fatalf("tool class = %q, want git-host", c.GetToolClass())
	}
	if authzer.lastUser != "user:alice" {
		t.Fatalf("caller subject = %q, want user:alice", authzer.lastUser)
	}
}

func TestSearchTools_UnavailableWhenNotWired(t *testing.T) {
	svc := &HarnessCallbackService{logger: slog.Default()}
	_, err := svc.SearchTools(context.Background(),
		&harnesspb.SearchToolsRequest{Context: &harnesspb.ContextInfo{}})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable when not wired, got %v", err)
	}
}

func TestSearchTools_RequiresRunID(t *testing.T) {
	svc := &HarnessCallbackService{
		agentSkills: noAgentSkillStore, skillLoadSink: noSkillLoadSink,
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

// fakeConnectors is the one MCP client of the daemon, in a test.
type fakeConnectors struct {
	tools   []catalog.ToolEntry
	listErr error
	result  any
	callErr error
	called  *[]string
}

func (f fakeConnectors) ListConnectorTools(context.Context, string) ([]catalog.ToolEntry, error) {
	return f.tools, f.listErr
}

func (f fakeConnectors) CallConnectorTool(_ context.Context, tenant, connector, tool string, _ map[string]any) (any, error) {
	if f.called != nil {
		*f.called = append(*f.called, tenant+"/"+connector+"/"+tool)
	}
	return f.result, f.callErr
}
