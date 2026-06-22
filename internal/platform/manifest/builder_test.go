package manifest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	manifestpb "github.com/zeroroot-ai/sdk/api/gen/gibson/manifest/v1"
)

// ------------------------------------------------------------------
// test doubles
// ------------------------------------------------------------------

type fakeFGA struct {
	resolve           func(ctx context.Context, userID, tenantID string) ([]capabilitygrant.Capability, error)
	crossRules        func(ctx context.Context, subjectFGA string, components []capabilitygrant.ComponentRef) ([]capabilitygrant.CrossRule, error)
	intersection      func(ctx context.Context, apID, ownerID, tenantID string) ([]capabilitygrant.ComponentRef, error)
	resolveCalls      int
	crossCalls        int
	intersectionCalls int
}

func (f *fakeFGA) ResolveCapabilities(ctx context.Context, userID, tenantID string) ([]capabilitygrant.Capability, error) {
	f.resolveCalls++
	return f.resolve(ctx, userID, tenantID)
}

func (f *fakeFGA) ResolveCrossComponentRules(ctx context.Context, subjectFGA string, components []capabilitygrant.ComponentRef) ([]capabilitygrant.CrossRule, error) {
	f.crossCalls++
	if f.crossRules == nil {
		return nil, nil
	}
	return f.crossRules(ctx, subjectFGA, components)
}

func (f *fakeFGA) ResolveAgentPrincipalIntersection(ctx context.Context, apID, ownerID, tenantID string) ([]capabilitygrant.ComponentRef, error) {
	f.intersectionCalls++
	return f.intersection(ctx, apID, ownerID, tenantID)
}

type fakeRegistry struct {
	infos []component.ComponentInfo
}

func (r *fakeRegistry) DiscoverAll(ctx context.Context, tenantID, kind string) ([]component.ComponentInfo, error) {
	return r.infos, nil
}

// ------------------------------------------------------------------

func newTestBuilder(t *testing.T, fga FGAResolver, reg RegistrySource) (Builder, Signer, VersionStore) {
	t.Helper()
	sk, err := GenerateSignerKey("k1")
	if err != nil {
		t.Fatalf("GenerateSignerKey: %v", err)
	}
	s, err := NewSigner("k1", []SignerKey{sk})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	vs := NewVersionStore(rdb, time.Second)

	b, err := NewBuilder(BuilderDeps{
		FGA:      fga,
		Registry: reg,
		Signer:   s,
		Versions: vs,
	}, BuilderConfig{TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return b, s, vs
}

func TestBuilder_UserSubjectHappyPath(t *testing.T) {
	fga := &fakeFGA{
		resolve: func(ctx context.Context, userID, tenantID string) ([]capabilitygrant.Capability, error) {
			return []capabilitygrant.Capability{
				{Name: "execute:tool:nmap", ComponentRef: "component:nmap", Kind: "tool"},
				{Name: "configure:plugin:gitlab", ComponentRef: "component:gitlab", Kind: "plugin"},
			}, nil
		},
	}
	reg := &fakeRegistry{infos: []component.ComponentInfo{
		{Kind: "tool", Name: "nmap", Version: "1.0", TenantID: "_system"},
		{Kind: "plugin", Name: "gitlab", Version: "2.1", TenantID: "tenant-acme"},
		{Kind: "tool", Name: "unreachable", Version: "0.0", TenantID: "_system"}, // has no perms — must be dropped
	}}
	b, s, _ := newTestBuilder(t, fga, reg)

	m, err := b.Build(context.Background(), ManifestSubject{
		Type: SubjectTypeUser, ID: "alice", TenantID: "tenant-acme",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.TenantId != "tenant-acme" {
		t.Fatalf("TenantId = %q", m.TenantId)
	}
	if m.Subject != "user:alice" {
		t.Fatalf("Subject = %q", m.Subject)
	}
	if len(m.Tools) != 1 || m.Tools[0].Name != "nmap" {
		t.Fatalf("Tools = %+v", m.Tools)
	}
	if len(m.Plugins) != 1 || m.Plugins[0].Name != "gitlab" {
		t.Fatalf("Plugins = %+v", m.Plugins)
	}
	if len(m.Agents) != 0 {
		t.Fatalf("Agents should be empty, got %+v", m.Agents)
	}
	if !m.Tools[0].IsSystem {
		t.Fatalf("nmap should be flagged is_system")
	}
	if m.Plugins[0].IsSystem {
		t.Fatalf("gitlab should NOT be is_system (tenant-acme owned)")
	}
	// Signature must verify.
	if err := s.Verify(m); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Version is 0 for a freshly-initialised VersionStore.
	if m.ManifestVersion != 0 {
		t.Fatalf("ManifestVersion = %d, want 0", m.ManifestVersion)
	}
	if m.ManifestId == "" || !m.ExpiresAt.AsTime().After(m.IssuedAt.AsTime()) {
		t.Fatalf("bad timestamps / id: %+v", m)
	}
}

func TestBuilder_AgentPrincipalIntersectionNarrowsScope(t *testing.T) {
	// Owner can_execute {nmap, sslyze}; agent can_execute {nmap, gitlab}
	// → intersection {nmap} only. The builder must drop gitlab.
	fga := &fakeFGA{
		resolve: func(ctx context.Context, userID, tenantID string) ([]capabilitygrant.Capability, error) {
			if userID == "owner-1" {
				return []capabilitygrant.Capability{
					{Name: "execute:tool:nmap", ComponentRef: "component:nmap", Kind: "tool"},
					{Name: "execute:tool:sslyze", ComponentRef: "component:sslyze", Kind: "tool"},
				}, nil
			}
			return nil, errors.New("unexpected user subject: " + userID)
		},
		intersection: func(ctx context.Context, apID, ownerID, tenantID string) ([]capabilitygrant.ComponentRef, error) {
			return []capabilitygrant.ComponentRef{{Name: "nmap", Kind: "tool"}}, nil
		},
	}
	reg := &fakeRegistry{infos: []component.ComponentInfo{
		{Kind: "tool", Name: "nmap", TenantID: "_system"},
		{Kind: "tool", Name: "sslyze", TenantID: "_system"},
	}}
	b, _, _ := newTestBuilder(t, fga, reg)

	m, err := b.Build(context.Background(), ManifestSubject{
		Type:        SubjectTypeAgentPrincipal,
		ID:          "agent-1",
		OwnerUserID: "owner-1",
		TenantID:    "tenant-acme",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(m.Tools) != 1 || m.Tools[0].Name != "nmap" {
		t.Fatalf("Tools = %+v; expected only nmap after intersection", m.Tools)
	}
	if m.Subject != "agent_principal:agent-1" {
		t.Fatalf("Subject = %q", m.Subject)
	}
}

func TestBuilder_CrossComponentRulesPropagate(t *testing.T) {
	fga := &fakeFGA{
		resolve: func(ctx context.Context, userID, tenantID string) ([]capabilitygrant.Capability, error) {
			return []capabilitygrant.Capability{
				{Name: "execute:tool:nmap", ComponentRef: "component:nmap", Kind: "tool"},
				{Name: "execute:plugin:gitlab", ComponentRef: "component:gitlab", Kind: "plugin"},
			}, nil
		},
		crossRules: func(ctx context.Context, subjectFGA string, components []capabilitygrant.ComponentRef) ([]capabilitygrant.CrossRule, error) {
			return []capabilitygrant.CrossRule{
				{Source: subjectFGA, Target: "component:gitlab", Effect: capabilitygrant.EffectDeny, Reason: "fga_deny"},
			}, nil
		},
	}
	reg := &fakeRegistry{infos: []component.ComponentInfo{
		{Kind: "tool", Name: "nmap", TenantID: "_system"},
		{Kind: "plugin", Name: "gitlab", TenantID: "tenant-acme"},
	}}
	b, _, _ := newTestBuilder(t, fga, reg)

	m, err := b.Build(context.Background(), ManifestSubject{Type: SubjectTypeUser, ID: "alice", TenantID: "tenant-acme"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(m.CrossComponentRules) != 1 {
		t.Fatalf("CrossComponentRules len = %d", len(m.CrossComponentRules))
	}
	rule := m.CrossComponentRules[0]
	if rule.Effect != manifestpb.CrossComponentRule_EFFECT_DENY {
		t.Fatalf("Effect = %v", rule.Effect)
	}
	if rule.SourceComponentRef != "user:alice" || rule.TargetComponentRef != "component:gitlab" {
		t.Fatalf("rule = %+v", rule)
	}
}

func TestBuilder_FailsClosedOnFGAError(t *testing.T) {
	fga := &fakeFGA{
		resolve: func(ctx context.Context, userID, tenantID string) ([]capabilitygrant.Capability, error) {
			return nil, errors.New("fga down")
		},
	}
	b, _, _ := newTestBuilder(t, fga, &fakeRegistry{})
	_, err := b.Build(context.Background(), ManifestSubject{Type: SubjectTypeUser, ID: "alice", TenantID: "tenant-acme"})
	if err == nil {
		t.Fatalf("expected error when FGA fails")
	}
}

func TestBuilder_MissingTenantErrors(t *testing.T) {
	fga := &fakeFGA{resolve: func(ctx context.Context, userID, tenantID string) ([]capabilitygrant.Capability, error) {
		return nil, nil
	}}
	b, _, _ := newTestBuilder(t, fga, &fakeRegistry{})
	_, err := b.Build(context.Background(), ManifestSubject{Type: SubjectTypeUser, ID: "alice"})
	if err == nil {
		t.Fatalf("expected error when tenantID missing")
	}
}

func TestBuilder_MissingAgentOwnerErrors(t *testing.T) {
	b, _, _ := newTestBuilder(t, &fakeFGA{resolve: func(ctx context.Context, u, ten string) ([]capabilitygrant.Capability, error) { return nil, nil }}, &fakeRegistry{})
	_, err := b.Build(context.Background(), ManifestSubject{Type: SubjectTypeAgentPrincipal, ID: "agent", TenantID: "t"})
	if err == nil {
		t.Fatalf("expected error when agent owner missing")
	}
}

func TestBuilder_VersionStampFromStore(t *testing.T) {
	fga := &fakeFGA{resolve: func(ctx context.Context, u, ten string) ([]capabilitygrant.Capability, error) { return nil, nil }}
	b, _, vs := newTestBuilder(t, fga, &fakeRegistry{})
	// Bump to 3 before Build.
	for i := 0; i < 3; i++ {
		if _, err := vs.Bump(context.Background(), "tenant-v"); err != nil {
			t.Fatalf("Bump: %v", err)
		}
	}
	m, err := b.Build(context.Background(), ManifestSubject{Type: SubjectTypeUser, ID: "alice", TenantID: "tenant-v"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.ManifestVersion != 3 {
		t.Fatalf("ManifestVersion = %d, want 3", m.ManifestVersion)
	}
}

func TestBuilder_Build_LatencyUnder100msSmallScope(t *testing.T) {
	fga := &fakeFGA{resolve: func(ctx context.Context, u, ten string) ([]capabilitygrant.Capability, error) {
		caps := make([]capabilitygrant.Capability, 50)
		for i := range caps {
			name := "c" + itoa(i)
			caps[i] = capabilitygrant.Capability{Name: "execute:tool:" + name, ComponentRef: "component:" + name, Kind: "tool"}
		}
		return caps, nil
	}}
	infos := make([]component.ComponentInfo, 50)
	for i := range infos {
		infos[i] = component.ComponentInfo{Kind: "tool", Name: "c" + itoa(i), TenantID: "_system"}
	}
	reg := &fakeRegistry{infos: infos}
	b, _, _ := newTestBuilder(t, fga, reg)

	start := time.Now()
	if _, err := b.Build(context.Background(), ManifestSubject{Type: SubjectTypeUser, ID: "alice", TenantID: "tenant-acme"}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("Build took %v (>100ms budget for 50 components with fake deps)", d)
	}
}

// itoa without strconv to keep the test dep surface minimal.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [16]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
