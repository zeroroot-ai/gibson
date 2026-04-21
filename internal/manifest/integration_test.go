package manifest

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/capabilitygrant"
	"github.com/zero-day-ai/gibson/internal/component"
	manifestpb "github.com/zero-day-ai/sdk/api/gen/gibson/manifest/v1"
)

// stubAuthorizer is a bench-weight authz.Authorizer that returns
// preseeded ListObjects / Check responses and counts Write/Delete calls.
type stubAuthorizer struct {
	listObjects map[string][]string // key = "<user>|<relation>|<type>"
	checks      map[string]bool     // key = "<user>|<relation>|<object>"
	writes      int64
}

func (s *stubAuthorizer) Check(_ context.Context, user, relation, object string) (bool, error) {
	return s.checks[user+"|"+relation+"|"+object], nil
}
func (s *stubAuthorizer) BatchCheck(_ context.Context, req []authz.CheckRequest) ([]bool, error) {
	out := make([]bool, len(req))
	for i, r := range req {
		out[i] = s.checks[r.User+"|"+r.Relation+"|"+r.Object]
	}
	return out, nil
}
func (s *stubAuthorizer) ListObjects(_ context.Context, user, relation, objectType string) ([]string, error) {
	return s.listObjects[user+"|"+relation+"|"+objectType], nil
}
func (s *stubAuthorizer) ListUsers(_ context.Context, _, _, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubAuthorizer) Write(_ context.Context, _ []authz.Tuple) error {
	atomic.AddInt64(&s.writes, 1)
	return nil
}
func (s *stubAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (s *stubAuthorizer) StoreID() string                                 { return "test" }
func (s *stubAuthorizer) ModelID() string                                 { return "test" }
func (s *stubAuthorizer) Close() error                                    { return nil }

// stubRegistry returns a fixed component.ComponentInfo slice on DiscoverAll.
type stubRegistry struct {
	infos []component.ComponentInfo
}

func (r *stubRegistry) Register(_ context.Context, _, _, _ string, _ component.ComponentInfo) (string, error) {
	return "", nil
}
func (r *stubRegistry) Deregister(_ context.Context, _, _, _, _ string) error { return nil }
func (r *stubRegistry) RefreshTTL(_ context.Context, _, _, _, _ string) error { return nil }
func (r *stubRegistry) Discover(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *stubRegistry) DiscoverAll(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return r.infos, nil
}
func (r *stubRegistry) ListTenantComponents(_ context.Context, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *stubRegistry) DiscoverTenantOnly(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *stubRegistry) DiscoverSystemOnly(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}

// TestIntegration_FullPipeline exercises Builder + Notifier + WatchHub
// + FGAObserver across a miniredis instance with mock FGA and registry.
// Covers the key end-to-end invariant: an FGA write through the
// FGAObserver should bump manifest_version AND deliver an invalidation
// event to a connected WatchHub subscriber.
func TestIntegration_FullPipeline(t *testing.T) {
	ctx := context.Background()
	mr, rdb := newMiniredis(t)
	_ = mr

	// --- Daemon-side wiring ------------------------------------------------
	vs := NewVersionStore(rdb, 100*time.Millisecond)
	inv := NewInvalidator(rdb, nil)
	notifier := NewNotifier(vs, inv, nil, nil)

	stubAuth := &stubAuthorizer{
		listObjects: map[string][]string{
			"user:alice|can_execute|component":              {"component:nmap"},
			"user:alice|can_read|component":                 {"component:gitlab"},
			"user:alice|can_configure|component":            nil,
			"agent_principal:A|cannot_invoke|component":     {"component:gitlab"},
			"agent_principal:A|can_be_invoked_by|component": nil,
			"user:alice|can_be_invoked_by|component":        nil,
		},
	}
	observedAuth := NewFGAObserver(stubAuth, notifier, nil)

	reg := &stubRegistry{infos: []component.ComponentInfo{
		{Kind: "tool", Name: "nmap", TenantID: "_system"},
		{Kind: "plugin", Name: "gitlab", TenantID: "tenant-acme"},
	}}
	observedReg := NewRegistryObserver(reg, notifier, nil)

	bridge := capabilitygrant.NewFGABridge(observedAuth, observedReg, nil)
	signerKey, err := GenerateSignerKey("k1")
	if err != nil {
		t.Fatalf("signer key: %v", err)
	}
	signer, err := NewSigner("k1", []SignerKey{signerKey})
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	builder, err := NewBuilder(BuilderDeps{
		FGA:      bridge,
		Registry: observedReg,
		Signer:   signer,
		Versions: vs,
	}, BuilderConfig{TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("builder: %v", err)
	}

	// --- WatchHub -----------------------------------------------------------
	hub := NewWatchHub(rdb, nil, time.Hour, 8)
	if err := hub.Start(ctx); err != nil {
		t.Fatalf("hub start: %v", err)
	}
	defer hub.Stop()
	// Wait for psubscribe to install.
	time.Sleep(80 * time.Millisecond)

	sub, unsub := hub.Subscribe("acme")
	defer unsub()

	// --- Build a manifest (user:alice / tenant:acme) -----------------------
	m, err := builder.Build(ctx, ManifestSubject{
		Type:     SubjectTypeUser,
		ID:       "alice",
		TenantID: "acme",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.ManifestVersion != 0 {
		t.Fatalf("ManifestVersion = %d, want 0 for fresh tenant", m.ManifestVersion)
	}
	if len(m.Tools) != 1 || m.Tools[0].Name != "nmap" {
		t.Fatalf("Tools = %+v", m.Tools)
	}
	if err := signer.Verify(m); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// --- FGA write via observed authorizer -> Bump + Publish ---------------
	if err := observedAuth.Write(ctx, []authz.Tuple{
		{User: "user:alice", Relation: "can_execute", Object: "tenant:acme"},
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Manifest version must have bumped.
	v, err := vs.Current(ctx, "acme")
	if err != nil || v == 0 {
		t.Fatalf("Current after Write: v=%d err=%v", v, err)
	}
	// Invalidation event must reach the subscriber.
	select {
	case ev := <-sub:
		if ev.EventType != manifestpb.ManifestInvalidationEvent_EVENT_TYPE_INVALIDATED {
			t.Fatalf("event type = %v", ev.EventType)
		}
		if ev.Reason != "fga_tuple_write" {
			t.Fatalf("reason = %q", ev.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for invalidation fanout")
	}

	// --- Build again: version must reflect the bump ------------------------
	m2, err := builder.Build(ctx, ManifestSubject{Type: SubjectTypeUser, ID: "alice", TenantID: "acme"})
	if err != nil {
		t.Fatalf("Build2: %v", err)
	}
	if m2.ManifestVersion != v {
		t.Fatalf("second manifest version = %d, want %d", m2.ManifestVersion, v)
	}
}

// TestIntegration_AgentPrincipalCrossDeny confirms that when an
// agent_principal has cannot_invoke against a component, the manifest's
// cross_component_rules surfaces a DENY.
func TestIntegration_AgentPrincipalCrossDeny(t *testing.T) {
	ctx := context.Background()
	_, rdb := newMiniredis(t)

	stubAuth := &stubAuthorizer{
		listObjects: map[string][]string{
			"user:owner|can_execute|component":              {"component:gitlab"},
			"user:owner|can_read|component":                 nil,
			"user:owner|can_configure|component":            nil,
			"agent_principal:A|can_execute|component":       {"component:gitlab"},
			"agent_principal:A|can_read|component":          nil,
			"agent_principal:A|can_configure|component":     nil,
			"agent_principal:A|cannot_invoke|component":     {"component:gitlab"},
			"agent_principal:A|can_be_invoked_by|component": nil,
		},
	}
	reg := &stubRegistry{infos: []component.ComponentInfo{
		{Kind: "plugin", Name: "gitlab", TenantID: "tenant-acme"},
	}}
	bridge := capabilitygrant.NewFGABridge(stubAuth, reg, nil)
	signerKey, _ := GenerateSignerKey("k1")
	signer, _ := NewSigner("k1", []SignerKey{signerKey})
	vs := NewVersionStore(rdb, time.Second)
	builder, _ := NewBuilder(BuilderDeps{
		FGA: bridge, Registry: reg, Signer: signer, Versions: vs,
	}, BuilderConfig{TTL: time.Minute})

	m, err := builder.Build(ctx, ManifestSubject{
		Type:        SubjectTypeAgentPrincipal,
		ID:          "A",
		OwnerUserID: "owner",
		TenantID:    "acme",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// gitlab is in scope (both owner + agent can_execute), but the
	// agent_principal has cannot_invoke → a DENY rule must appear.
	if len(m.CrossComponentRules) != 1 {
		t.Fatalf("expected 1 cross-component rule, got %d", len(m.CrossComponentRules))
	}
	r := m.CrossComponentRules[0]
	if r.Effect != manifestpb.CrossComponentRule_EFFECT_DENY {
		t.Fatalf("effect = %v", r.Effect)
	}
	if r.SourceComponentRef != "agent_principal:A" || r.TargetComponentRef != "component:gitlab" {
		t.Fatalf("rule = %+v", r)
	}
}
