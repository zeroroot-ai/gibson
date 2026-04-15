package harness

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/zero-day-ai/sdk/taxonomy"
)

// fakeOverlayLoader is a deterministic in-memory ruleOverlayLoader.
type fakeOverlayLoader struct {
	mu       sync.Mutex
	tenants  []string
	overlays map[string][]taxonomy.Rule
	listErr  error
	loadErr  map[string]error
}

func (f *fakeOverlayLoader) ListTenants(ctx context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]string, len(f.tenants))
	copy(out, f.tenants)
	return out, nil
}

func (f *fakeOverlayLoader) LoadOverlay(ctx context.Context, tenantID string) ([]taxonomy.Rule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.loadErr[tenantID]; ok {
		return nil, err
	}
	return f.overlays[tenantID], nil
}

func TestRuleRegistry_SystemOnly(t *testing.T) {
	systemRules := []taxonomy.Rule{
		{ID: "SYS.1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{Equals: map[string]string{"action": "tool_call"}}},
	}
	r := NewComplianceRuleRegistry(systemRules, nil, nil)
	got := r.Get("tenant-a")
	if len(got) != 1 {
		t.Errorf("got %d rules; want 1", len(got))
	}
}

func TestRuleRegistry_OverlayMerge(t *testing.T) {
	systemRules := []taxonomy.Rule{
		{ID: "SYS.1", Framework: "F", ControlID: "C1", Matcher: taxonomy.Matcher{Equals: map[string]string{"action": "tool_call"}}},
	}
	loader := &fakeOverlayLoader{
		tenants: []string{"tenant-a"},
		overlays: map[string][]taxonomy.Rule{
			"tenant-a": {
				{ID: "TENANT.1", Framework: "F", ControlID: "C2", Matcher: taxonomy.Matcher{Equals: map[string]string{"action": "llm_call"}}},
			},
		},
	}
	r := NewComplianceRuleRegistry(systemRules, loader, nil)
	r.reloadOnce(context.Background())

	got := r.Get("tenant-a")
	if len(got) != 2 {
		t.Errorf("tenant-a should see system + overlay = 2 rules, got %d", len(got))
	}
	// Other tenant sees only system rules.
	got = r.Get("tenant-b")
	if len(got) != 1 {
		t.Errorf("tenant-b should see system only, got %d", len(got))
	}
}

func TestRuleRegistry_ReservedNamespaceRejection(t *testing.T) {
	loader := &fakeOverlayLoader{
		tenants: []string{"tenant-a"},
		overlays: map[string][]taxonomy.Rule{
			"tenant-a": {
				{ID: "PLATFORM.SNEAKY", Framework: "F", ControlID: "C", Matcher: taxonomy.Matcher{Equals: map[string]string{"action": "tool_call"}}},
				{ID: "SYSTEM.ALSO_SNEAKY", Framework: "F", ControlID: "C", Matcher: taxonomy.Matcher{Equals: map[string]string{"action": "tool_call"}}},
				{ID: "OK.1", Framework: "F", ControlID: "C", Matcher: taxonomy.Matcher{Equals: map[string]string{"action": "tool_call"}}},
			},
		},
	}
	r := NewComplianceRuleRegistry(nil, loader, nil)
	r.reloadOnce(context.Background())

	got := r.Get("tenant-a")
	if len(got) != 1 {
		t.Errorf("reserved namespace rules should be dropped, leaving 1; got %d", len(got))
	}
	if got[0].ID != "OK.1" {
		t.Errorf("wrong rule retained: %v", got[0].ID)
	}
}

func TestRuleRegistry_BrokenOverlayDoesNotAffectOthers(t *testing.T) {
	loader := &fakeOverlayLoader{
		tenants: []string{"tenant-a", "tenant-b"},
		overlays: map[string][]taxonomy.Rule{
			"tenant-b": {
				{ID: "OK.1", Framework: "F", ControlID: "C", Matcher: taxonomy.Matcher{Equals: map[string]string{"action": "tool_call"}}},
			},
		},
		loadErr: map[string]error{
			"tenant-a": errors.New("redis timeout"),
		},
	}
	r := NewComplianceRuleRegistry(nil, loader, nil)
	r.reloadOnce(context.Background())

	if got := len(r.Get("tenant-b")); got != 1 {
		t.Errorf("tenant-b overlay should load despite tenant-a failure; got %d", got)
	}
}

func TestIsReservedRuleID(t *testing.T) {
	cases := map[string]bool{
		"PLATFORM.X":         true,
		"_system.Y":          true,
		"SYSTEM.Z":           true,
		"MYCORP.CUSTOM":      false,
		"SOC2.CC7.1":         false,
		"platform.lowercase": false, // case sensitive
	}
	for id, want := range cases {
		if got := isReservedRuleID(id); got != want {
			t.Errorf("isReservedRuleID(%q) = %v; want %v", id, got, want)
		}
	}
}
