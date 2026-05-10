package health_test

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/zero-day-ai/gibson/internal/sandbox/health"
)

// TestSetTier_ProductionLabel verifies the gauge renders the expected
// metric series after a SetTier("production") call.
func TestSetTier_ProductionLabel(t *testing.T) {
	t.Cleanup(health.ResetForTest)
	health.ResetForTest()

	health.SetTier("production")

	want := `
# HELP gibson_setec_tier Active Setec sandbox tier indicator. Value is always 1; the ` + "`tier`" + ` label carries the meaningful signal (today: only "production").
# TYPE gibson_setec_tier gauge
gibson_setec_tier{tier="production"} 1
`
	if err := testutil.GatherAndCompare(prometheus.DefaultGatherer, strings.NewReader(want), "gibson_setec_tier"); err != nil {
		t.Fatalf("metric mismatch: %v", err)
	}
}

// TestSetTier_EmptyIsNoOp asserts an empty tier value does not register
// any series — the daemon would surface a missing gauge to the dashboard
// rather than render a blank label.
func TestSetTier_EmptyIsNoOp(t *testing.T) {
	t.Cleanup(health.ResetForTest)
	health.ResetForTest()

	health.SetTier("")

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == "gibson_setec_tier" && len(f.Metric) > 0 {
			t.Fatalf("expected zero gibson_setec_tier series after SetTier(\"\"), got %d", len(f.Metric))
		}
	}
}

// TestSetTier_OnlyFirstCallTakesEffect proves the once-guard: a second
// SetTier call with a different label does NOT flap the gauge to a new
// series. R10.1 explicitly forbids gauge flapping.
func TestSetTier_OnlyFirstCallTakesEffect(t *testing.T) {
	t.Cleanup(health.ResetForTest)
	health.ResetForTest()

	health.SetTier("production")
	health.SetTier("alpha-test") // attacker / buggy caller

	want := `
# HELP gibson_setec_tier Active Setec sandbox tier indicator. Value is always 1; the ` + "`tier`" + ` label carries the meaningful signal (today: only "production").
# TYPE gibson_setec_tier gauge
gibson_setec_tier{tier="production"} 1
`
	if err := testutil.GatherAndCompare(prometheus.DefaultGatherer, strings.NewReader(want), "gibson_setec_tier"); err != nil {
		t.Fatalf("once-guard broken — second SetTier flapped the gauge: %v", err)
	}
}
