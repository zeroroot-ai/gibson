package contextkeys_test

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/contextkeys"
)

// TestNewStringKeysRoundtrip verifies that each new string-typed key can be
// set and retrieved, and returns zero value + false when absent.
func TestNewStringKeysRoundtrip(t *testing.T) {
	t.Parallel()

	type stringCase struct {
		name   string
		withFn func(context.Context, string) context.Context
		getFn  func(context.Context) (string, bool)
		value  string
	}

	cases := []stringCase{
		{
			name:   "TenantID",
			withFn: contextkeys.WithTenantID,
			getFn:  contextkeys.GetTenantID,
			value:  "tenant-abc",
		},
		{
			name:   "ActorID",
			withFn: contextkeys.WithActorID,
			getFn:  contextkeys.GetActorID,
			value:  "user-xyz",
		},
		{
			name:   "APIKeyID",
			withFn: contextkeys.WithAPIKeyID,
			getFn:  contextkeys.GetAPIKeyID,
			value:  "gsk_key123",
		},
		{
			name:   "ParentAgentRunID",
			withFn: contextkeys.WithParentAgentRunID,
			getFn:  contextkeys.GetParentAgentRunID,
			value:  "run-parent-001",
		},
		{
			name:   "CallerComponent",
			withFn: contextkeys.WithCallerComponent,
			getFn:  contextkeys.GetCallerComponent,
			value:  "agent:gitlab-agent",
		},
		{
			name:   "CallerComponentVersion",
			withFn: contextkeys.WithCallerComponentVersion,
			getFn:  contextkeys.GetCallerComponentVersion,
			value:  "v1.2.3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/present", func(t *testing.T) {
			t.Parallel()
			ctx := tc.withFn(context.Background(), tc.value)
			got, ok := tc.getFn(ctx)
			if !ok {
				t.Errorf("%s: expected ok=true, got false", tc.name)
			}
			if got != tc.value {
				t.Errorf("%s: expected %q, got %q", tc.name, tc.value, got)
			}
		})

		t.Run(tc.name+"/absent", func(t *testing.T) {
			t.Parallel()
			got, ok := tc.getFn(context.Background())
			if ok {
				t.Errorf("%s: expected ok=false on empty context, got true", tc.name)
			}
			if got != "" {
				t.Errorf("%s: expected empty string on missing key, got %q", tc.name, got)
			}
		})
	}
}

// TestCallerChainRoundtrip verifies the []string CallerChain key behaves correctly.
func TestCallerChainRoundtrip(t *testing.T) {
	t.Parallel()

	t.Run("present", func(t *testing.T) {
		t.Parallel()
		chain := []string{"run-a", "run-b", "run-c"}
		ctx := contextkeys.WithCallerChain(context.Background(), chain)
		got, ok := contextkeys.GetCallerChain(ctx)
		if !ok {
			t.Fatal("CallerChain: expected ok=true, got false")
		}
		if len(got) != len(chain) {
			t.Fatalf("CallerChain: expected length %d, got %d", len(chain), len(got))
		}
		for i, v := range chain {
			if got[i] != v {
				t.Errorf("CallerChain[%d]: expected %q, got %q", i, v, got[i])
			}
		}
	})

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		got, ok := contextkeys.GetCallerChain(context.Background())
		if ok {
			t.Error("CallerChain: expected ok=false on empty context, got true")
		}
		if got != nil {
			t.Errorf("CallerChain: expected nil on missing key, got %v", got)
		}
	})

	t.Run("empty_slice", func(t *testing.T) {
		t.Parallel()
		ctx := contextkeys.WithCallerChain(context.Background(), []string{})
		got, ok := contextkeys.GetCallerChain(ctx)
		if !ok {
			t.Fatal("CallerChain: expected ok=true for empty slice, got false")
		}
		if len(got) != 0 {
			t.Errorf("CallerChain: expected empty slice, got %v", got)
		}
	})
}

// TestExistingKeysUnchanged ensures the original 5 keys still compile and work.
func TestExistingKeysUnchanged(t *testing.T) {
	t.Parallel()

	ctx := contextkeys.WithAgentRunID(context.Background(), "run-001")
	if got := contextkeys.GetAgentRunID(ctx); got != "run-001" {
		t.Errorf("AgentRunID: expected run-001, got %q", got)
	}

	ctx = contextkeys.WithToolExecutionID(context.Background(), "tex-001")
	if got := contextkeys.GetToolExecutionID(ctx); got != "tex-001" {
		t.Errorf("ToolExecutionID: expected tex-001, got %q", got)
	}

	ctx = contextkeys.WithMissionRunID(context.Background(), "mrun-001")
	if got := contextkeys.GetMissionRunID(ctx); got != "mrun-001" {
		t.Errorf("MissionRunID: expected mrun-001, got %q", got)
	}
}

// TestNoPanicOnMissingKeys asserts that all getters are safe on a bare context.
// The race detector validates no data races across goroutines sharing a context.
func TestNoPanicOnMissingKeys(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// string keys — must not panic
	contextkeys.GetTenantID(ctx)               //nolint:errcheck
	contextkeys.GetActorID(ctx)                //nolint:errcheck
	contextkeys.GetAPIKeyID(ctx)               //nolint:errcheck
	contextkeys.GetParentAgentRunID(ctx)       //nolint:errcheck
	contextkeys.GetCallerComponent(ctx)        //nolint:errcheck
	contextkeys.GetCallerComponentVersion(ctx) //nolint:errcheck

	// slice key — must not panic and must return nil
	chain, ok := contextkeys.GetCallerChain(ctx)
	if ok || chain != nil {
		t.Errorf("expected (nil, false) for missing CallerChain, got (%v, %v)", chain, ok)
	}
}
