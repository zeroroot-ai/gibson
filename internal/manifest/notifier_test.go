package manifest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/component"
)

type recordingInvalidator struct {
	mu    sync.Mutex
	calls []struct{ tenant, reason string }
}

func (r *recordingInvalidator) Publish(ctx context.Context, tenantID, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, struct{ tenant, reason string }{tenantID, reason})
}

func (r *recordingInvalidator) Calls() []struct{ tenant, reason string } {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]struct{ tenant, reason string }, len(r.calls))
	copy(out, r.calls)
	return out
}

type countingVersions struct {
	mu     sync.Mutex
	bumps  map[string]uint64
}

func newCountingVersions() *countingVersions { return &countingVersions{bumps: map[string]uint64{}} }

func (c *countingVersions) Bump(_ context.Context, tenantID string) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bumps[tenantID]++
	return c.bumps[tenantID], nil
}

func (c *countingVersions) Current(_ context.Context, tenantID string) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bumps[tenantID], nil
}

func (c *countingVersions) BumpCount(tenant string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bumps[tenant]
}

func TestNotifier_BumpsAndPublishes(t *testing.T) {
	inv := &recordingInvalidator{}
	vs := newCountingVersions()
	n := NewNotifier(vs, inv, nil, nil)

	n.Notify(context.Background(), "tenant-a", "fga_tuple_write")
	if vs.BumpCount("tenant-a") != 1 {
		t.Fatalf("bump count = %d", vs.BumpCount("tenant-a"))
	}
	if len(inv.Calls()) != 1 {
		t.Fatalf("publish calls = %d", len(inv.Calls()))
	}
}

func TestNotifier_DeduplicatesBursts(t *testing.T) {
	inv := &recordingInvalidator{}
	vs := newCountingVersions()
	n := NewNotifier(vs, inv, nil, nil)
	for i := 0; i < 10; i++ {
		n.Notify(context.Background(), "tenant-a", "fga_tuple_write")
	}
	if got := vs.BumpCount("tenant-a"); got != 1 {
		t.Fatalf("bursty Notify produced %d bumps, want 1", got)
	}
	if len(inv.Calls()) != 1 {
		t.Fatalf("bursty Notify produced %d publishes, want 1", len(inv.Calls()))
	}
}

func TestNotifier_EmptyTenantSkipped(t *testing.T) {
	inv := &recordingInvalidator{}
	vs := newCountingVersions()
	n := NewNotifier(vs, inv, nil, nil)
	n.Notify(context.Background(), "", "whatever")
	if len(inv.Calls()) != 0 || vs.BumpCount("") != 0 {
		t.Fatalf("empty tenant should not notify")
	}
}

func TestNotifier_SystemFanout(t *testing.T) {
	inv := &recordingInvalidator{}
	vs := newCountingVersions()
	enum := &StaticTenantEnumerator{Tenants: []string{"t1", "t2", "t3"}}
	n := NewNotifier(vs, inv, enum, nil)
	n.Notify(context.Background(), "_system", "component_registered:tool:nmap")
	if got := len(inv.Calls()); got != 3 {
		t.Fatalf("system fanout emitted %d invalidations, want 3", got)
	}
	for _, c := range inv.Calls() {
		if c.reason == "" || c.tenant == "_system" {
			t.Fatalf("unexpected fanout entry: %+v", c)
		}
	}
}

func TestNotifier_SystemFanoutDevFallback(t *testing.T) {
	inv := &recordingInvalidator{}
	vs := newCountingVersions()
	n := NewNotifier(vs, inv, nil, nil) // nil enumerator = dev fallback
	n.Notify(context.Background(), "_system", "fga_tuple_write")
	if len(inv.Calls()) != 1 || inv.Calls()[0].tenant != "_system" {
		t.Fatalf("dev fallback should emit one event on _system, got %+v", inv.Calls())
	}
}

func TestFGAObserver_NotifiesOnWriteSuccess(t *testing.T) {
	inner := &fakeAuthorizer{}
	inv := &recordingInvalidator{}
	vs := newCountingVersions()
	n := NewNotifier(vs, inv, nil, nil)
	obs := NewFGAObserver(inner, n, nil)

	tuples := []authz.Tuple{
		{User: "user:alice", Relation: "member", Object: "tenant:acme"},
		{User: "user:bob", Relation: "can_execute", Object: "component:nmap"},
	}
	if err := obs.Write(context.Background(), tuples); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// One notify for tenant:acme; the second tuple has no tenant so no fire.
	if got := len(inv.Calls()); got != 1 {
		t.Fatalf("publishes = %d, want 1", got)
	}
	if inv.Calls()[0].tenant != "acme" {
		t.Fatalf("tenant = %q", inv.Calls()[0].tenant)
	}
}

func TestFGAObserver_NoNotifyOnWriteFailure(t *testing.T) {
	inner := &fakeAuthorizer{writeErr: errTest}
	inv := &recordingInvalidator{}
	vs := newCountingVersions()
	n := NewNotifier(vs, inv, nil, nil)
	obs := NewFGAObserver(inner, n, nil)

	_ = obs.Write(context.Background(), []authz.Tuple{{Object: "tenant:acme"}})
	if len(inv.Calls()) != 0 {
		t.Fatalf("failed write must not notify")
	}
}

type fakeAuthorizer struct {
	writeErr error
}

var errTest = &fakeError{msg: "forced"}

type fakeError struct{ msg string }

func (e *fakeError) Error() string { return e.msg }

func (f *fakeAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (f *fakeAuthorizer) BatchCheck(context.Context, []authz.CheckRequest) ([]bool, error) {
	return nil, nil
}
func (f *fakeAuthorizer) Write(_ context.Context, _ []authz.Tuple) error  { return f.writeErr }
func (f *fakeAuthorizer) Delete(_ context.Context, _ []authz.Tuple) error { return nil }
func (f *fakeAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthorizer) ListUsers(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthorizer) StoreID() string { return "" }
func (f *fakeAuthorizer) ModelID() string { return "" }
func (f *fakeAuthorizer) Close() error    { return nil }

func TestRegistryObserver_NotifiesOnRegister(t *testing.T) {
	inner := &fakeRegistry2{}
	inv := &recordingInvalidator{}
	vs := newCountingVersions()
	n := NewNotifier(vs, inv, nil, nil)
	obs := NewRegistryObserver(inner, n, nil)

	if _, err := obs.Register(context.Background(), "acme", "tool", "nmap", component.ComponentInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := obs.Deregister(context.Background(), "acme", "tool", "nmap", "i-1"); err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if len(inv.Calls()) != 2 {
		t.Fatalf("publishes = %d, want 2", len(inv.Calls()))
	}

	// RefreshTTL is NOT a notify trigger.
	if err := obs.RefreshTTL(context.Background(), "acme", "tool", "nmap", "i-1"); err != nil {
		t.Fatalf("RefreshTTL: %v", err)
	}
	if len(inv.Calls()) != 2 {
		t.Fatalf("heartbeat should not notify; publishes = %d", len(inv.Calls()))
	}
}

type fakeRegistry2 struct{}

func (*fakeRegistry2) Register(_ context.Context, _, _, _ string, _ component.ComponentInfo) (string, error) {
	return "i-1", nil
}
func (*fakeRegistry2) Deregister(_ context.Context, _, _, _, _ string) error { return nil }
func (*fakeRegistry2) RefreshTTL(_ context.Context, _, _, _, _ string) error { return nil }
func (*fakeRegistry2) Discover(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (*fakeRegistry2) DiscoverAll(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (*fakeRegistry2) ListTenantComponents(_ context.Context, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (*fakeRegistry2) DiscoverTenantOnly(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (*fakeRegistry2) DiscoverSystemOnly(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}

func TestNotifier_DedupeWindowResets(t *testing.T) {
	inv := &recordingInvalidator{}
	vs := newCountingVersions()
	n := NewNotifier(vs, inv, nil, nil).(*notifier)
	n.dedupWindow = 10 * time.Millisecond
	ctx := context.Background()
	n.Notify(ctx, "tenant-a", "r")
	time.Sleep(20 * time.Millisecond)
	n.Notify(ctx, "tenant-a", "r")
	if c := len(inv.Calls()); c != 2 {
		t.Fatalf("expected two notifies across the dedup window, got %d", c)
	}
}

