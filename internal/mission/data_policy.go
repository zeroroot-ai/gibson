package mission

import (
	"fmt"
)

// DataPolicy defines data scoping and reuse behavior for agents in mission nodes.
// This declarative policy controls:
//   - Where stored data is visible (output_scope)
//   - What data the agent can query (input_scope)
//   - Whether to skip execution when data exists (reuse)
//
// Policies are defined per-node in mission YAML and enforced by the harness.
// Agents remain unaware of scoping - the harness transparently applies filters.
//
// Example YAML usage:
//
//	nodes:
//	  - id: recon
//	    agent: network-recon
//	    data_policy:
//	      output_scope: mission      # Data visible to all runs
//	      input_scope: mission       # Query sees all mission runs
//	      reuse: skip                # Skip if data exists
type DataPolicy struct {
	// OutputScope controls where stored data is visible.
	// Valid values: "mission_run", "mission", "global"
	// Default: "mission"
	//
	// - mission_run: Data only visible within current run
	// - mission: Data visible to all runs of this mission
	// - global: Data visible across all missions
	OutputScope string `yaml:"output_scope"`

	// InputScope controls what data queries can see.
	// Valid values: "mission_run", "mission", "global"
	// Default: "mission"
	//
	// - mission_run: Only query current run's data
	// - mission: Query all runs of this mission
	// - global: Query across all missions
	InputScope string `yaml:"input_scope"`

	// Reuse controls execution skipping behavior.
	// Valid values: "skip", "always", "never"
	// Default: "never"
	//
	// - skip: Skip execution if data exists in input_scope
	// - always: Never execute (requires prior data)
	// - never: Always execute regardless of existing data
	Reuse string `yaml:"reuse"`
}

// Scope constants for OutputScope and InputScope validation
const (
	// ScopeMissionRun limits visibility to the current mission run only
	ScopeMissionRun = "mission_run"

	// ScopeMission allows visibility across all runs of the same mission
	ScopeMission = "mission"

	// ScopeGlobal allows visibility across all missions
	ScopeGlobal = "global"
)

// Reuse constants for Reuse validation
const (
	// ReuseSkip skips execution if data already exists in scope
	ReuseSkip = "skip"

	// ReuseAlways never executes the agent (always reuses existing data)
	ReuseAlways = "always"

	// ReuseNever always executes the agent regardless of existing data
	ReuseNever = "never"
)

// SetDefaults applies default values to unset fields.
// This ensures policy fields always have valid values.
//
// Defaults:
//   - OutputScope: "mission"
//   - InputScope: "mission"
//   - Reuse: "never"
func (p *DataPolicy) SetDefaults() {
	if p.OutputScope == "" {
		p.OutputScope = ScopeMission
	}
	if p.InputScope == "" {
		p.InputScope = ScopeMission
	}
	if p.Reuse == "" {
		p.Reuse = ReuseNever
	}
}

// Validate checks that all policy fields contain valid values.
// Returns an error if any field has an invalid value.
//
// Valid values:
//   - OutputScope: "mission_run", "mission", "global"
//   - InputScope: "mission_run", "mission", "global"
//   - Reuse: "skip", "always", "never"
//
// This should be called after SetDefaults() to ensure fields are populated.
func (p *DataPolicy) Validate() error {
	// Validate OutputScope
	switch p.OutputScope {
	case ScopeMissionRun, ScopeMission, ScopeGlobal:
		// Valid
	default:
		return fmt.Errorf("invalid output_scope value '%s': must be mission_run|mission|global", p.OutputScope)
	}

	// Validate InputScope
	switch p.InputScope {
	case ScopeMissionRun, ScopeMission, ScopeGlobal:
		// Valid
	default:
		return fmt.Errorf("invalid input_scope value '%s': must be mission_run|mission|global", p.InputScope)
	}

	// Validate Reuse
	switch p.Reuse {
	case ReuseSkip, ReuseAlways, ReuseNever:
		// Valid
	default:
		return fmt.Errorf("invalid reuse value '%s': must be skip|always|never", p.Reuse)
	}

	return nil
}

// NewDataPolicy creates a DataPolicy with default values applied.
// This is a convenience constructor for creating policies programmatically.
//
// Returns a policy with:
//   - OutputScope: "mission"
//   - InputScope: "mission"
//   - Reuse: "never"
func NewDataPolicy() *DataPolicy {
	p := &DataPolicy{}
	p.SetDefaults()
	return p
}
