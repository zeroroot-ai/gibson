package plans

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoad_Canonical loads the real plans.yaml shipped next to this file.
// Authoritative smoke test; if plans.yaml is malformed or a required field
// is missing the operator will panic at startup, so catch it here first.
func TestLoad_Canonical(t *testing.T) {
	reg, err := Load(repoPlansPath(t))
	if err != nil {
		t.Fatalf("Load(canonical plans.yaml): %v", err)
	}

	wantIDs := []PlanID{PlanTeam, PlanOrg, PlanEnterprise, PlanEnterpriseDeploy}
	gotIDs := reg.IDs()
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("plan count: got %d, want %d", len(gotIDs), len(wantIDs))
	}
	for i, want := range wantIDs {
		if gotIDs[i] != want {
			t.Errorf("plan[%d]: got %q, want %q", i, gotIDs[i], want)
		}
	}

	team := reg.MustLookup(PlanTeam)
	if team.Quotas.ConcurrentMissions <= 0 {
		t.Errorf("team.concurrent_missions: got %d, want > 0", team.Quotas.ConcurrentMissions)
	}
	if team.Quotas.ConcurrentAgents <= 0 {
		t.Errorf("team.concurrent_agents: got %d, want > 0", team.Quotas.ConcurrentAgents)
	}

	// enterprise-deploy is the unlimited plan (0 = unlimited).
	ed := reg.MustLookup(PlanEnterpriseDeploy)
	if ed.Quotas.ConcurrentMissions != 0 {
		t.Errorf("enterprise-deploy.concurrent_missions: got %d, want 0 (unlimited)", ed.Quotas.ConcurrentMissions)
	}
	if ed.Quotas.ConcurrentAgents != 0 {
		t.Errorf("enterprise-deploy.concurrent_agents: got %d, want 0 (unlimited)", ed.Quotas.ConcurrentAgents)
	}
	if !ed.Pricing.ContactSales {
		t.Errorf("enterprise-deploy.pricing.contactSales: got false, want true")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatalf("Load(missing): want error, got nil")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("error should mention read, got %v", err)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("this: is: not: valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load(bad): want error, got nil")
	}
}

func TestLoad_UnknownID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown-id.yaml")
	body := `version: v1
plans:
  - id: solo
    displayName: Solo
    tagline: t
    pricing:
      monthlyUSD: 1
    trialDays: 14
    quotas:
      concurrent_missions: 1
      concurrent_agents: 1
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load(legacy id): want error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown id") {
		t.Errorf("error should mention unknown id, got %v", err)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	// omit displayName
	body := `version: v1
plans:
  - id: team
    tagline: t
    pricing:
      monthlyUSD: 1
    trialDays: 14
    quotas:
      concurrent_missions: 1
      concurrent_agents: 1
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load(missing displayName): want error, got nil")
	}
	if !strings.Contains(err.Error(), "displayName") {
		t.Errorf("error should mention displayName, got %v", err)
	}
}

func TestLoad_Duplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dup.yaml")
	body := `version: v1
plans:
  - id: team
    displayName: Team 1
    tagline: t
    pricing:
      monthlyUSD: 1
    trialDays: 14
    quotas:
      concurrent_missions: 1
      concurrent_agents: 1
  - id: team
    displayName: Team 2
    tagline: t
    pricing:
      monthlyUSD: 2
    trialDays: 14
    quotas:
      concurrent_missions: 2
      concurrent_agents: 2
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load(duplicate id): want error, got nil")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("error should mention duplicate, got %v", err)
	}
}

func TestLoad_NegativeQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "neg.yaml")
	body := `version: v1
plans:
  - id: team
    displayName: Team
    tagline: t
    pricing:
      monthlyUSD: 1
    trialDays: 14
    quotas:
      concurrent_missions: -1
      concurrent_agents: 1
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load(negative quota): want error, got nil")
	}
	if !strings.Contains(err.Error(), "concurrent_missions") {
		t.Errorf("error should mention the offending field, got %v", err)
	}
}

func TestLoad_PricingRequired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-pricing.yaml")
	body := `version: v1
plans:
  - id: team
    displayName: Team
    tagline: t
    pricing: {}
    quotas:
      concurrent_missions: 1
      concurrent_agents: 1
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load(empty pricing): want error, got nil")
	}
	if !strings.Contains(err.Error(), "pricing") {
		t.Errorf("error should mention pricing, got %v", err)
	}
}

// TestLookup_QuotasPlanIDBackfilled guards tenant-operator#288: after Load the
// Quotas.PlanID field must equal the plan's canonical ID string so the
// entitlements client can pass it to UpsertTenantQuota without a separate
// parameter.
func TestLookup_QuotasPlanIDBackfilled(t *testing.T) {
	reg, err := Load(repoPlansPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, id := range reg.IDs() {
		p := reg.MustLookup(id)
		if got, want := p.Quotas.PlanID, string(id); got != want {
			t.Errorf("plan %q: Quotas.PlanID = %q, want %q", id, got, want)
		}
	}
}

func TestLookup_Unknown(t *testing.T) {
	reg, err := Load(repoPlansPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := reg.Lookup(PlanID("does-not-exist")); err == nil {
		t.Errorf("Lookup(nonexistent): want error, got nil")
	}
}

func TestLookup_NilRegistry(t *testing.T) {
	var r *Registry
	if _, err := r.Lookup(PlanTeam); err == nil {
		t.Errorf("nil registry Lookup: want error, got nil")
	}
}

func TestMustLookup_Panics(t *testing.T) {
	reg, err := Load(repoPlansPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("MustLookup(nonexistent): want panic, got none")
		}
	}()
	_ = reg.MustLookup(PlanID("missing"))
}

// repoPlansPath resolves plans.yaml relative to this test file, without
// assuming anything about the CWD the test runner uses.
func repoPlansPath(t *testing.T) string {
	t.Helper()
	p := "plans.yaml"
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if _, err := os.Stat(filepath.Join("plans", "plans.yaml")); err == nil {
		return filepath.Join("plans", "plans.yaml")
	}
	t.Fatalf("cannot locate plans.yaml relative to test CWD")
	return ""
}

// TestLoad_TrialDays locks the card-first-signup trial contract
// (tenant-operator#357): every self-serve paid tier declares the 14-day
// trial; the unbilled contactSales tier declares none.
func TestLoad_TrialDays(t *testing.T) {
	reg, err := Load(repoPlansPath(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, p := range reg.Plans {
		if p.Pricing.ContactSales {
			if p.TrialDays != 0 {
				t.Errorf("plan %q: contactSales plan must carry no trial, got %d", p.ID, p.TrialDays)
			}
			continue
		}
		if p.TrialDays != 14 {
			t.Errorf("plan %q: trialDays = %d, want 14", p.ID, p.TrialDays)
		}
	}
}

// TestLoad_TrialDaysValidation locks the two validation rules.
func TestLoad_TrialDaysValidation(t *testing.T) {
	cases := []struct {
		name, plan, wantErr string
	}{
		{
			name: "self-serve without trial rejected",
			plan: `  - id: team
    displayName: Team
    tagline: t
    pricing:
      monthlyUSD: 1
    quotas:
      concurrent_missions: 1
      concurrent_agents: 1
`,
			wantErr: "trialDays must be a positive integer",
		},
		{
			name: "contactSales with trial rejected",
			plan: `  - id: enterprise-deploy
    displayName: Fed
    tagline: t
    pricing:
      contactSales: true
    trialDays: 14
    quotas:
      concurrent_missions: 1
      concurrent_agents: 1
`,
			wantErr: "trialDays is forbidden on contactSales plans",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "plans.yaml")
			if err := os.WriteFile(path, []byte("version: v1\nplans:\n"+tc.plan), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
