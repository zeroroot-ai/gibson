package plans

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// PlanID is the canonical identifier for a Gibson plan. The four values
// below are the only ids recognised anywhere in the system.
type PlanID string

const (
	PlanTeam             PlanID = "team"
	PlanOrg              PlanID = "org"
	PlanEnterprise       PlanID = "enterprise"
	PlanEnterpriseDeploy PlanID = "enterprise-deploy"
)

// allPlanIDs lists every valid PlanID for validation. Iteration order
// matches the order published on the pricing page.
var allPlanIDs = []PlanID{
	PlanTeam,
	PlanOrg,
	PlanEnterprise,
	PlanEnterpriseDeploy,
}

// Quotas holds a plan's runtime enforcement values. A value of 0 means
// "unlimited" — the daemon must treat 0 as no enforcement. Both quotas
// are server-side enforced; see spec plans-and-quotas-simplification.
type Quotas struct {
	// PlanID is the canonical plan identifier (e.g. "team", "org",
	// "enterprise"). Populated by the Registry when the plan is looked up;
	// not present in the YAML file. Written to tenant_quotas.plan_id.
	PlanID string `yaml:"-"`
	// ConcurrentMissions: max missions in non-terminal execution state.
	ConcurrentMissions int `yaml:"concurrent_missions"`
	// ConcurrentAgents: max agents bound to in-flight mission tasks.
	// Idle-but-connected agents do NOT count toward this quota.
	ConcurrentAgents int `yaml:"concurrent_agents"`
	// ConcurrentConnectors: max hosted MCP connector instances running at
	// once (ADR-0047 facet 3). 0 = unlimited.
	ConcurrentConnectors int `yaml:"concurrent_connectors"`
}

// Pricing carries display-side pricing metadata for a plan. At least one
// of MonthlyUSD/AnnualUSD/ContactSales must be set.
type Pricing struct {
	MonthlyUSD       *float64 `yaml:"monthlyUSD,omitempty"`
	AnnualUSD        *float64 `yaml:"annualUSD,omitempty"`
	AnnualSavingsPct *float64 `yaml:"annualSavingsPct,omitempty"`
	ContactSales     bool     `yaml:"contactSales,omitempty"`
}

// Plan is one entry in the canonical registry.
type Plan struct {
	ID              PlanID  `yaml:"id"`
	DisplayName     string  `yaml:"displayName"`
	Tagline         string  `yaml:"tagline"`
	StripeProductID *string `yaml:"stripeProductId,omitempty"`
	Pricing         Pricing `yaml:"pricing"`
	// TrialDays is the card-first signup trial length for self-serve paid
	// tiers (checkout sessions set trial_period_days from this — the single
	// source; consumers must not hardcode a trial length). 0 on contactSales
	// plans, which carry no Stripe subscription.
	TrialDays int    `yaml:"trialDays,omitempty"`
	Quotas    Quotas `yaml:"quotas"`
}

// Registry is the loaded, validated set of plans.
type Registry struct {
	Version string `yaml:"version"`
	Plans   []Plan `yaml:"plans"`
	byID    map[PlanID]*Plan
}

// Load reads the plan registry from the given filesystem path and returns a
// fully-validated Registry. Load rejects unknown plan ids, missing required
// fields, and duplicate ids.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("plans: read %s: %w", path, err)
	}

	var reg Registry
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&reg); err != nil {
		return nil, fmt.Errorf("plans: unmarshal %s: %w", path, err)
	}

	if err := reg.validate(); err != nil {
		return nil, fmt.Errorf("plans: validate %s: %w", path, err)
	}

	reg.byID = make(map[PlanID]*Plan, len(reg.Plans))
	for i := range reg.Plans {
		// Backfill PlanID into Quotas so callers get a self-contained Quotas
		// value without needing to thread the plan ID separately.
		reg.Plans[i].Quotas.PlanID = string(reg.Plans[i].ID)
		reg.byID[reg.Plans[i].ID] = &reg.Plans[i]
	}

	return &reg, nil
}

// Lookup returns the Plan matching id, or an error if the id is unknown.
func (r *Registry) Lookup(id PlanID) (*Plan, error) {
	if r == nil || r.byID == nil {
		return nil, fmt.Errorf("plans: registry not initialised")
	}
	p, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("plans: unknown plan id %q", id)
	}
	return p, nil
}

// MustLookup is Lookup with a panic on error. Intended for call sites where
// the plan id is known to have been validated already (e.g. after the CRD
// admission has confirmed the enum value).
func (r *Registry) MustLookup(id PlanID) *Plan {
	p, err := r.Lookup(id)
	if err != nil {
		panic(err)
	}
	return p
}

// IDs returns every PlanID present in the registry in pricing-page order.
func (r *Registry) IDs() []PlanID {
	out := make([]PlanID, len(r.Plans))
	for i, p := range r.Plans {
		out[i] = p.ID
	}
	return out
}

// validate runs internal checks over the Registry after YAML unmarshal.
func (r *Registry) validate() error {
	if r.Version == "" {
		return fmt.Errorf("missing version")
	}
	if len(r.Plans) == 0 {
		return fmt.Errorf("no plans defined")
	}

	validIDs := make(map[PlanID]struct{}, len(allPlanIDs))
	for _, id := range allPlanIDs {
		validIDs[id] = struct{}{}
	}

	seen := make(map[PlanID]int, len(r.Plans))
	for i, p := range r.Plans {
		if p.ID == "" {
			return fmt.Errorf("plan index %d: id is required", i)
		}
		if _, ok := validIDs[p.ID]; !ok {
			return fmt.Errorf("plan index %d: unknown id %q", i, p.ID)
		}
		if j, dup := seen[p.ID]; dup {
			return fmt.Errorf("plan id %q defined twice (indices %d and %d)", p.ID, j, i)
		}
		seen[p.ID] = i

		if p.DisplayName == "" {
			return fmt.Errorf("plan %q: displayName is required", p.ID)
		}
		if p.Tagline == "" {
			return fmt.Errorf("plan %q: tagline is required", p.ID)
		}
		// Both quotas must be non-negative integers. 0 = unlimited.
		if p.Quotas.ConcurrentMissions < 0 {
			return fmt.Errorf(
				"plan %q: quota concurrent_missions cannot be negative (got %d)",
				p.ID, p.Quotas.ConcurrentMissions,
			)
		}
		if p.Quotas.ConcurrentAgents < 0 {
			return fmt.Errorf("plan %q: quota concurrent_agents cannot be negative (got %d)", p.ID, p.Quotas.ConcurrentAgents)
		}
		// At least one of monthlyUSD/annualUSD/contactSales must be present.
		if p.Pricing.MonthlyUSD == nil && p.Pricing.AnnualUSD == nil && !p.Pricing.ContactSales {
			return fmt.Errorf("plan %q: pricing must set at least one of monthlyUSD, annualUSD, or contactSales=true", p.ID)
		}
		// Trial contract (tenant-operator#357): every self-serve paid tier
		// declares a positive trial; contactSales plans are unbilled and
		// must not declare one.
		if p.Pricing.ContactSales {
			if p.TrialDays != 0 {
				return fmt.Errorf("plan %q: trialDays is forbidden on contactSales plans (got %d)", p.ID, p.TrialDays)
			}
		} else if p.TrialDays <= 0 {
			return fmt.Errorf(
				"plan %q: trialDays must be a positive integer on self-serve paid tiers (got %d)",
				p.ID, p.TrialDays,
			)
		}
	}
	return nil
}
