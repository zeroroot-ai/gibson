package capabilitygrant

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/component"
)

// ---------------------------------------------------------------------------
// Tests: ResolveCrossComponentRules
// ---------------------------------------------------------------------------

func TestResolveCrossComponentRules_DenyOverridesAllow(t *testing.T) {
	// Agent has both cannot_invoke AND can_be_invoked_by for the same
	// target — the DENY must win and the ALLOW must not be emitted.
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, relation, objectType string) ([]string, error) {
			if user == "agent_principal:A" && relation == "cannot_invoke" && objectType == "component" {
				return []string{"component:gitlab"}, nil
			}
			if user == "agent_principal:A" && relation == "can_be_invoked_by" && objectType == "component" {
				return []string{"component:gitlab", "component:slack"}, nil
			}
			return nil, nil
		},
	}
	b := NewFGABridge(auth, &mockRegistry{}, noopLogger())

	scope := []ComponentRef{{Name: "gitlab", Kind: "plugin"}, {Name: "slack", Kind: "plugin"}}
	rules, err := b.ResolveCrossComponentRules(context.Background(), "agent_principal:A", scope)
	require.NoError(t, err)

	// Order independence: sort by target for comparison.
	sort.Slice(rules, func(i, j int) bool { return rules[i].Target < rules[j].Target })
	require.Len(t, rules, 2)
	assert.Equal(t, CrossRule{Source: "agent_principal:A", Target: "component:gitlab", Effect: EffectDeny, Reason: "fga_deny"}, rules[0])
	assert.Equal(t, CrossRule{Source: "agent_principal:A", Target: "component:slack", Effect: EffectAllow, Reason: "fga_grant"}, rules[1])
}

func TestResolveCrossComponentRules_OutOfScopeTargetsSkipped(t *testing.T) {
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, relation, objectType string) ([]string, error) {
			if relation == "cannot_invoke" {
				return []string{"component:unscoped"}, nil
			}
			return nil, nil
		},
	}
	b := NewFGABridge(auth, &mockRegistry{}, noopLogger())
	rules, err := b.ResolveCrossComponentRules(context.Background(), "agent_principal:A",
		[]ComponentRef{{Name: "other", Kind: "tool"}})
	require.NoError(t, err)
	assert.Empty(t, rules)
}

func TestResolveCrossComponentRules_ComponentSubjectSkipsCannotInvoke(t *testing.T) {
	// Component subjects do NOT get the cannot_invoke query (the FGA
	// schema places that relation only on agent_principal).
	called := map[string]bool{}
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, relation, objectType string) ([]string, error) {
			called[relation] = true
			if relation == "can_be_invoked_by" {
				return []string{"component:gitlab"}, nil
			}
			return nil, nil
		},
	}
	b := NewFGABridge(auth, &mockRegistry{}, noopLogger())
	rules, err := b.ResolveCrossComponentRules(context.Background(), "component:nmap-agent",
		[]ComponentRef{{Name: "gitlab", Kind: "plugin"}})
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, EffectAllow, rules[0].Effect)
	assert.False(t, called["cannot_invoke"], "cannot_invoke should not be queried for component subjects")
}

func TestResolveCrossComponentRules_FGAErrorPropagates(t *testing.T) {
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, relation, objectType string) ([]string, error) {
			return nil, errors.New("fga unavailable")
		},
	}
	b := NewFGABridge(auth, &mockRegistry{}, noopLogger())
	_, err := b.ResolveCrossComponentRules(context.Background(), "agent_principal:A",
		[]ComponentRef{{Name: "x", Kind: "tool"}})
	require.Error(t, err)
}

func TestResolveCrossComponentRules_EmptyInputShortCircuits(t *testing.T) {
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, relation, objectType string) ([]string, error) {
			t.Fatalf("should not be called for empty scope")
			return nil, nil
		},
	}
	b := NewFGABridge(auth, &mockRegistry{}, noopLogger())
	rules, err := b.ResolveCrossComponentRules(context.Background(), "agent_principal:A", nil)
	require.NoError(t, err)
	assert.Empty(t, rules)
}

func TestResolveCrossComponentRules_EmptySubjectErrors(t *testing.T) {
	b := NewFGABridge(&mockAuthorizer{}, &mockRegistry{}, noopLogger())
	_, err := b.ResolveCrossComponentRules(context.Background(), "",
		[]ComponentRef{{Name: "x", Kind: "tool"}})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Tests: ResolveAgentPrincipalIntersection
// ---------------------------------------------------------------------------

func TestResolveAgentPrincipalIntersection_DropsUnownedComponents(t *testing.T) {
	// owner can_execute {component:nmap, component:sslyze}
	// agent  can_execute {component:nmap, component:gitlab}
	// → intersection is {component:nmap} only — gitlab must be dropped
	// because the owner cannot reach it.
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, relation, objectType string) ([]string, error) {
			switch {
			case user == "user:owner" && relation == "can_execute":
				return []string{"component:nmap", "component:sslyze"}, nil
			case user == "agent_principal:A" && relation == "can_execute":
				return []string{"component:nmap", "component:gitlab"}, nil
			}
			return nil, nil
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(tenant, kind string) ([]component.ComponentInfo, error) {
			return []component.ComponentInfo{
				{Name: "nmap", Kind: "tool"},
				{Name: "sslyze", Kind: "tool"},
				{Name: "gitlab", Kind: "plugin"},
			}, nil
		},
	}
	b := NewFGABridge(auth, reg, noopLogger())

	refs, err := b.ResolveAgentPrincipalIntersection(context.Background(), "A", "owner", "tenant-acme")
	require.NoError(t, err)
	require.Len(t, refs, 1)
	assert.Equal(t, "nmap", refs[0].Name)
	assert.Equal(t, "tool", refs[0].Kind)
}

func TestResolveAgentPrincipalIntersection_EmptyOwnerReturnsEmpty(t *testing.T) {
	auth := &mockAuthorizer{
		listObjectsFunc: func(user, relation, objectType string) ([]string, error) {
			if user == "user:owner" {
				return nil, nil
			}
			if user == "agent_principal:A" && relation == "can_execute" {
				return []string{"component:nmap"}, nil
			}
			return nil, nil
		},
	}
	reg := &mockRegistry{
		discoverAllFunc: func(tenant, kind string) ([]component.ComponentInfo, error) {
			return []component.ComponentInfo{{Name: "nmap", Kind: "tool"}}, nil
		},
	}
	b := NewFGABridge(auth, reg, noopLogger())
	refs, err := b.ResolveAgentPrincipalIntersection(context.Background(), "A", "owner", "tenant-acme")
	require.NoError(t, err)
	assert.Empty(t, refs)
}

func TestResolveAgentPrincipalIntersection_MissingIDsError(t *testing.T) {
	b := NewFGABridge(&mockAuthorizer{}, &mockRegistry{}, noopLogger())
	_, err := b.ResolveAgentPrincipalIntersection(context.Background(), "", "owner", "t")
	require.Error(t, err)
	_, err = b.ResolveAgentPrincipalIntersection(context.Background(), "A", "", "t")
	require.Error(t, err)
}
