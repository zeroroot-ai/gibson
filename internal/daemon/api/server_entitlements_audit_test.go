package api

// Unit tests for the entitlements audit classifiers + emit helpers.
//
// Spec: access-matrix-finish task 23, R6 AC 1-3.

import (
	"context"
	"testing"

	"github.com/zero-day-ai/sdk/auth"
)

func TestClassifyRelationAction(t *testing.T) {
	cases := []struct {
		relation string
		want     string
	}{
		{"can_read", "read"},
		{"can_configure", "write"},
		{"can_execute", "execute"},
		{"component_read_enabled", "read"},
		{"component_write_enabled", "write"},
		{"component_execute_enabled", "execute"},
		{"tenant_read_disabled", "read"},
		{"team_write_disabled", "write"},
		{"user_execute_disabled", "execute"},
		{"member", ""},
		{"admin", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.relation, func(t *testing.T) {
			if got := classifyRelationAction(tc.relation); got != tc.want {
				t.Fatalf("classifyRelationAction(%q) = %q, want %q", tc.relation, got, tc.want)
			}
		})
	}
}

func TestClassifyScopeType(t *testing.T) {
	cases := []struct {
		user string
		want string
	}{
		{"tenant:acme", "tenant"},
		{"team:acme-red#member", "team"},
		{"user:alice", "user"},
		{"agent_principal:uuid-acme", "component"},
		{"component:plugin/gitlab", "component"},
		{"other:xyz", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.user, func(t *testing.T) {
			if got := classifyScopeType(tc.user); got != tc.want {
				t.Fatalf("classifyScopeType(%q) = %q, want %q", tc.user, got, tc.want)
			}
		})
	}
}

func TestClassifyActorSource(t *testing.T) {
	cases := []struct {
		name    string
		ident   *auth.Identity
		want    string
		subject string
	}{
		{"nil identity → system", nil, "system", ""},
		{"apikey → tenant_admin", &auth.Identity{Subject: "gsk_abc", Issuer: "apikey"}, "tenant_admin", ""},
		{"zitadel → user", &auth.Identity{Subject: "u-1", Issuer: "zitadel"}, "user", ""},
		{"capability-grant → user", &auth.Identity{Subject: "agent-1", Issuer: "capability-grant"}, "user", ""},
		{"spiffe platform → platform", &auth.Identity{Subject: "spiffe://zero-day.ai/platform/tenant-operator", Issuer: "spiffe"}, "platform", ""},
		{"spiffe non-platform → operator", &auth.Identity{Subject: "spiffe://zero-day.ai/dashboard", Issuer: "spiffe"}, "operator", ""},
		{"spiffe via subject prefix → platform", &auth.Identity{Subject: "spiffe://zero-day.ai/platform/dashboard", Issuer: "other"}, "platform", ""},
		{"unknown issuer → unknown", &auth.Identity{Subject: "x", Issuer: "weird"}, "unknown", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.ident != nil {
				ctx = auth.WithIdentity(ctx, *tc.ident)
			}
			got := classifyActorSource(ctx)
			if got != tc.want {
				t.Fatalf("classifyActorSource = %q, want %q", got, tc.want)
			}
		})
	}
}

// fakeAuditEmitter captures Log() calls for assertion.
type fakeAuditEmitter struct {
	calls []struct {
		Action, Resource, ResourceID string
		Details                      map[string]any
	}
	err error
}

func (f *fakeAuditEmitter) Log(ctx context.Context, action, resource, resourceID string, details map[string]any) error {
	f.calls = append(f.calls, struct {
		Action, Resource, ResourceID string
		Details                      map[string]any
	}{action, resource, resourceID, details})
	return f.err
}

func TestEmitAccessTupleChange_PopulatesAllFields(t *testing.T) {
	em := &fakeAuditEmitter{}
	tuple := struct{ User, Relation, Object string }{
		User:     "team:acme-red#member",
		Relation: "team_execute_disabled",
		Object:   "component:plugin/gitlab",
	}
	emitAccessTupleChange(context.Background(), em, "tenant_admin", tuple, "write", "dashboard: team execute deny")

	if len(em.calls) != 1 {
		t.Fatalf("expected 1 Log call, got %d", len(em.calls))
	}
	c := em.calls[0]
	if c.Action != "access_tuple_change" {
		t.Fatalf("action = %q, want access_tuple_change", c.Action)
	}
	if c.ResourceID != "component:plugin/gitlab" {
		t.Fatalf("resourceID = %q, want component:plugin/gitlab", c.ResourceID)
	}
	want := map[string]string{
		"tuple":          "team:acme-red#member#team_execute_disabled@component:plugin/gitlab",
		"tuple_user":     "team:acme-red#member",
		"tuple_relation": "team_execute_disabled",
		"tuple_object":   "component:plugin/gitlab",
		"action_class":   "execute",
		"scope_type":     "team",
		"operation":      "write",
		"reason":         "dashboard: team execute deny",
		"actor_source":   "tenant_admin",
	}
	for k, v := range want {
		got, ok := c.Details[k]
		if !ok {
			t.Fatalf("details missing key %q", k)
		}
		if got != v {
			t.Fatalf("details[%q] = %v, want %q", k, got, v)
		}
	}
}

func TestEmitAccessTupleChange_NilEmitter_NoPanic(t *testing.T) {
	// Must not panic when the emitter is nil (daemon running without audit).
	emitAccessTupleChange(context.Background(), nil, "system",
		struct{ User, Relation, Object string }{"u", "r", "o"}, "write", "test")
}

func TestEmitReconcileSummary(t *testing.T) {
	em := &fakeAuditEmitter{}
	emitReconcileSummary(context.Background(), em, "acme", "operator", ReconcileSummaryFields{
		Plan:                 "org",
		AddedFeatureTuples:   3,
		RemovedFeatureTuples: 1,
		QuotaDelta:           0,
		DurationMs:           142,
		Trigger:              "cr_change",
	})
	if len(em.calls) != 1 {
		t.Fatalf("expected 1 Log call, got %d", len(em.calls))
	}
	c := em.calls[0]
	if c.Action != "entitlements_reconcile" {
		t.Fatalf("action = %q", c.Action)
	}
	if c.ResourceID != "acme" {
		t.Fatalf("resourceID = %q, want acme", c.ResourceID)
	}
	if c.Details["plan"] != "org" {
		t.Fatalf("plan = %v", c.Details["plan"])
	}
	if c.Details["trigger"] != "cr_change" {
		t.Fatalf("trigger = %v", c.Details["trigger"])
	}
}
