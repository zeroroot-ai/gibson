// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// seedWorld submits entity events for scope and waits for the World to fold at
// least wantHosts hosts, so the projection reads a settled World.
func seedWorld(t *testing.T, eng *brain.Engine, scope string, wantHosts int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		hosts := 0
		for _, h := range eng.Hosts() {
			if h.ScopeID == scope {
				hosts++
			}
		}
		if hosts >= wantHosts {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("world never folded %d hosts for scope %q (got %d)", wantHosts, scope, hosts)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func newWorldViewTestSource(t *testing.T) (harness.WorldViewSource, *brain.Registry) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx)
	minter, err := newHandleMinter()
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	return worldViewSource(reg, minter), reg
}

func TestWorldViewSource_ProjectsScopedEntities(t *testing.T) {
	src, reg := newWorldViewTestSource(t)
	eng := reg.For("acme")
	eng.Submit(brain.HostObserved{ScopeID: "scope-a", Address: "10.0.0.1", OpenPorts: []int{22, 443}})
	eng.Submit(brain.HostObserved{ScopeID: "scope-a", Address: "10.0.0.2"})
	eng.Submit(brain.HostObserved{ScopeID: "scope-b", Address: "10.9.9.9"}) // other scope
	eng.Submit(brain.FindingRaised{ID: "f-1", Title: "open admin", ScopeID: "scope-a", Severity: "high", Address: "10.0.0.1"})
	seedWorld(t, eng, "scope-a", 2)

	res, err := src(context.Background(), harness.WorldViewQuery{Tenant: "acme", ScopeID: "scope-a", MissionID: "m-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated {
		t.Error("small slice must not be truncated")
	}

	kinds := map[harnesspb.WorldEntityKind]int{}
	var host1Handle string
	for _, e := range res.Entities {
		if e.Handle == "" {
			t.Errorf("every entity must carry a handle: %+v", e)
		}
		kinds[e.Kind]++
		if e.Kind == harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_HOST && e.Label == "10.0.0.1" {
			host1Handle = e.Handle
		}
	}
	if kinds[harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_HOST] != 2 {
		t.Errorf("want 2 hosts in scope-a, got %d (scope-b must be excluded)", kinds[harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_HOST])
	}
	if kinds[harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_FINDING] != 1 {
		t.Errorf("want 1 finding, got %d", kinds[harnesspb.WorldEntityKind_WORLD_ENTITY_KIND_FINDING])
	}
	if host1Handle == "" {
		t.Fatal("host 10.0.0.1 not projected")
	}

	// Unfocused slice is summarized: host carries an open_ports count, not the
	// full port list.
	for _, e := range res.Entities {
		if e.Handle == host1Handle {
			if e.Attributes["open_ports"] != "2" {
				t.Errorf("unfocused host summary should carry open_ports count, got %v", e.Attributes)
			}
			if _, full := e.Attributes["ports"]; full {
				t.Errorf("unfocused slice must not carry the full port list: %v", e.Attributes)
			}
		}
	}
}

func TestWorldViewSource_HandleStableAcrossReprojection(t *testing.T) {
	src, reg := newWorldViewTestSource(t)
	eng := reg.For("acme")
	eng.Submit(brain.HostObserved{ScopeID: "s", Address: "1.1.1.1"})
	seedWorld(t, eng, "s", 1)

	q := harness.WorldViewQuery{Tenant: "acme", ScopeID: "s"}
	a, _ := src(context.Background(), q)
	b, _ := src(context.Background(), q)
	if len(a.Entities) != 1 || len(b.Entities) != 1 {
		t.Fatalf("want 1 entity each, got %d/%d", len(a.Entities), len(b.Entities))
	}
	if a.Entities[0].Handle != b.Entities[0].Handle {
		t.Errorf("handle must be stable across re-projections: %q vs %q", a.Entities[0].Handle, b.Entities[0].Handle)
	}
}

func TestWorldViewSource_HandleScopeIsolated(t *testing.T) {
	src, reg := newWorldViewTestSource(t)
	eng := reg.For("acme")
	eng.Submit(brain.HostObserved{ScopeID: "s1", Address: "1.1.1.1"})
	eng.Submit(brain.HostObserved{ScopeID: "s2", Address: "1.1.1.1"}) // same address, different scope
	seedWorld(t, eng, "s1", 1)
	seedWorld(t, eng, "s2", 1)

	a, _ := src(context.Background(), harness.WorldViewQuery{Tenant: "acme", ScopeID: "s1"})
	b, _ := src(context.Background(), harness.WorldViewQuery{Tenant: "acme", ScopeID: "s2"})
	if a.Entities[0].Handle == b.Entities[0].Handle {
		t.Error("same address in two scopes must mint different handles (scope binds the handle)")
	}
}

func TestWorldViewSource_FocusZoomsIn(t *testing.T) {
	src, reg := newWorldViewTestSource(t)
	eng := reg.For("acme")
	eng.Submit(brain.HostObserved{ScopeID: "s", Address: "1.1.1.1", OpenPorts: []int{22, 80, 443}})
	eng.Submit(brain.HostObserved{ScopeID: "s", Address: "2.2.2.2"})
	seedWorld(t, eng, "s", 2)

	// Discover the handle from an unfocused slice.
	unfocused, _ := src(context.Background(), harness.WorldViewQuery{Tenant: "acme", ScopeID: "s"})
	var target string
	for _, e := range unfocused.Entities {
		if e.Label == "1.1.1.1" {
			target = e.Handle
		}
	}
	if target == "" {
		t.Fatal("host 1.1.1.1 not in unfocused slice")
	}

	focused, err := src(context.Background(), harness.WorldViewQuery{Tenant: "acme", ScopeID: "s", Focus: []string{target}})
	if err != nil {
		t.Fatal(err)
	}
	if len(focused.Entities) != 1 {
		t.Fatalf("focus must narrow to the named entity, got %d", len(focused.Entities))
	}
	// Focused slice is full detail: the port list is present.
	if focused.Entities[0].Attributes["ports"] != "22,80,443" {
		t.Errorf("focused host must carry the full port list, got %v", focused.Entities[0].Attributes)
	}
}

func TestWorldViewSource_FocusRefusesUnissuedHandle(t *testing.T) {
	src, reg := newWorldViewTestSource(t)
	eng := reg.For("acme")
	eng.Submit(brain.HostObserved{ScopeID: "s", Address: "1.1.1.1"})
	seedWorld(t, eng, "s", 1)

	_, err := src(context.Background(), harness.WorldViewQuery{Tenant: "acme", ScopeID: "s", Focus: []string{"not-a-real-handle"}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a handle never issued to this slice must be refused with PermissionDenied, got %v", err)
	}
}

func TestWorldViewSource_NilRegistryEmpty(t *testing.T) {
	src := worldViewSource(nil, mustMinter(t))
	res, err := src(context.Background(), harness.WorldViewQuery{Tenant: "acme", ScopeID: "s"})
	if err != nil || len(res.Entities) != 0 {
		t.Fatalf("nil registry must yield an empty slice, got %d entities err %v", len(res.Entities), err)
	}
}

func TestCapSlice_Truncates(t *testing.T) {
	all := make([]harness.WorldEntityRecord, worldViewProjectionCap+5)
	res := capSlice(all)
	if !res.Truncated || len(res.Entities) != worldViewProjectionCap {
		t.Fatalf("over-cap slice must truncate to the cap and report it: %d entities truncated=%v", len(res.Entities), res.Truncated)
	}
	res = capSlice(all[:3])
	if res.Truncated {
		t.Error("under-cap slice must not report truncation")
	}
}

// TestWorldViewAttributeHelpers covers the nil/fallback branches of the
// per-kind attribute projectors that the seeded-World tests do not reach.
func TestWorldViewAttributeHelpers(t *testing.T) {
	// credentialLabel falls back to kind when there is no username.
	if got := credentialLabel(brain.CredentialSnapshot{Kind: "token"}); got != "token" {
		t.Errorf("credentialLabel fallback: got %q", got)
	}
	if got := credentialLabel(brain.CredentialSnapshot{Username: "root", Kind: "password"}); got != "root" {
		t.Errorf("credentialLabel username: got %q", got)
	}
	// credentialAttributes is nil when kind is empty; hides username unless full.
	if credentialAttributes(brain.CredentialSnapshot{}, true) != nil {
		t.Error("credential with no kind must project no attributes")
	}
	if a := credentialAttributes(brain.CredentialSnapshot{Kind: "password", Username: "root"}, false); a["username"] != "" {
		t.Errorf("summary credential must not carry username: %v", a)
	}
	// accountAttributes is nil when kind is empty.
	if accountAttributes(brain.AccountSnapshot{}, false) != nil {
		t.Error("account with no kind must project no attributes")
	}
	// findingAttributes is nil when nothing projects.
	if findingAttributes(brain.FindingSnapshot{}, false) != nil {
		t.Error("empty finding must project no attributes")
	}
	// subdomainAttributes summary: nil with no addresses, count with addresses.
	if subdomainAttributes(brain.SubdomainSnapshot{}, false) != nil {
		t.Error("subdomain summary with no addresses must be nil")
	}
	if a := subdomainAttributes(brain.SubdomainSnapshot{Addresses: []string{"1.1.1.1", "2.2.2.2"}}, false); a["addresses"] != "2" {
		t.Errorf("subdomain summary address count: %v", a)
	}
	// servicePortLabels falls back to protocol when the service name is empty.
	h := brain.HostSnapshot{Services: map[int]brain.ServiceInfo{22: {Protocol: "tcp"}}}
	if got := servicePortLabels(h); got != "22/tcp" {
		t.Errorf("servicePortLabels protocol fallback: got %q", got)
	}
	// hostAttributes summary carries a surprise marker when present.
	if a := hostAttributes(brain.HostSnapshot{Surprise: "new-key", OpenPorts: []int{22}}, false); a["surprise"] != "new-key" {
		t.Errorf("host summary must carry surprise: %v", a)
	}
}

func mustMinter(t *testing.T) *handleMinter {
	t.Helper()
	m, err := newHandleMinter()
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	return m
}

// TestWorldViewSource_AllKindsSummaryAndFocus seeds every WorldEntityKind and
// exercises both the unfocused summary and the focused full-detail attribute
// projection for each, so the per-kind attribute helpers are all covered.
func TestWorldViewSource_AllKindsSummaryAndFocus(t *testing.T) {
	src, reg := newWorldViewTestSource(t)
	eng := reg.For("acme")
	eng.Submit(brain.HostObserved{ScopeID: "s", Address: "10.0.0.1", CloudID: "i-123", OpenPorts: []int{22, 443},
		Services: map[int]brain.ServiceInfo{443: {Protocol: "tcp", Name: "https"}}})
	eng.Submit(brain.DomainObserved{ScopeID: "s", Name: "example.com"})
	eng.Submit(brain.SubdomainObserved{ScopeID: "s", FQDN: "api.example.com", Domain: "example.com", Addresses: []string{"10.0.0.2"}})
	eng.Submit(brain.CredentialObserved{ScopeID: "s", SecretHash: "abc", Username: "root", CredentialKind: "password"})
	eng.Submit(brain.AccountObserved{ScopeID: "s", Identifier: "svc-acct", AccountKind: "service"})
	eng.Submit(brain.FindingRaised{ID: "f-1", Title: "weak cred", ScopeID: "s", Severity: "high", Address: "10.0.0.1", Description: "reused password"})
	seedWorld(t, eng, "s", 1)

	// Wait until all six kinds have folded.
	deadline := time.After(2 * time.Second)
	for {
		res, _ := src(context.Background(), harness.WorldViewQuery{Tenant: "acme", ScopeID: "s"})
		if len(res.Entities) >= 6 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("world never folded all 6 kinds, got %d", len(res.Entities))
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Unfocused summary: collect every handle, assert the summary attributes.
	unfocused, _ := src(context.Background(), harness.WorldViewQuery{Tenant: "acme", ScopeID: "s"})
	byLabel := map[string]harness.WorldEntityRecord{}
	handles := make([]string, 0, len(unfocused.Entities))
	for _, e := range unfocused.Entities {
		byLabel[e.Label] = e
		handles = append(handles, e.Handle)
	}
	if byLabel["root"].Attributes["kind"] != "password" {
		t.Errorf("credential summary kind: %v", byLabel["root"].Attributes)
	}
	if byLabel["root"].Attributes["username"] != "" {
		t.Errorf("unfocused credential must not reveal username: %v", byLabel["root"].Attributes)
	}
	if byLabel["svc-acct"].Attributes["kind"] != "service" {
		t.Errorf("account summary kind: %v", byLabel["svc-acct"].Attributes)
	}

	// Focused full detail across all kinds: covers every helper's full branch.
	focused, err := src(context.Background(), harness.WorldViewQuery{Tenant: "acme", ScopeID: "s", Focus: handles})
	if err != nil {
		t.Fatal(err)
	}
	fByLabel := map[string]harness.WorldEntityRecord{}
	for _, e := range focused.Entities {
		fByLabel[e.Label] = e
	}
	if fByLabel["10.0.0.1"].Attributes["ports"] != "22,443" {
		t.Errorf("focused host ports: %v", fByLabel["10.0.0.1"].Attributes)
	}
	if fByLabel["10.0.0.1"].Attributes["services"] != "443/https" {
		t.Errorf("focused host services: %v", fByLabel["10.0.0.1"].Attributes)
	}
	if fByLabel["10.0.0.1"].Attributes["cloud_id"] != "i-123" {
		t.Errorf("focused host cloud_id: %v", fByLabel["10.0.0.1"].Attributes)
	}
	if fByLabel["api.example.com"].Attributes["domain"] != "example.com" {
		t.Errorf("focused subdomain domain: %v", fByLabel["api.example.com"].Attributes)
	}
	if fByLabel["api.example.com"].Attributes["addresses"] != "10.0.0.2" {
		t.Errorf("focused subdomain addresses: %v", fByLabel["api.example.com"].Attributes)
	}
	if fByLabel["root"].Attributes["username"] != "root" {
		t.Errorf("focused credential username: %v", fByLabel["root"].Attributes)
	}
	if fByLabel["weak cred"].Attributes["description"] != "reused password" {
		t.Errorf("focused finding description: %v", fByLabel["weak cred"].Attributes)
	}
}
