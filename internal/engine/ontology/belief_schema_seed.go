// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

// belief_schema_seed.go is the SEED belief-PRM schema (ADR-0029 §2, §7): it
// replaces the hardcoded {reachable, exploitable, juicy} per-Host belief
// field (ADR-0005, internal/engine/brain/belief.go) with the same three
// variables, expressed as declarative schema instead of Go structs, so the
// belief engine (gibson#275/#276) can generalise beyond Host without a code
// change to this package.
//
// coreBeliefSchemaExtensionName mirrors ontology.Loader's "core/<file>"
// naming convention for taxonomy YAML extensions (loader.go).
const coreBeliefSchemaExtensionName = "core/belief-schema"

// SeedBeliefSchemaExtension returns the seed belief-PRM schema:
//
//   - Host is belief-bearing with the three seed variables from ADR-0005,
//     wired as a small dependency chain (reachable -> exploitable -> juicy)
//     matching the funnel the pre-PRM belief field already encodes: a target
//     cannot be exploitable if it is not reachable, and cannot be juicy if it
//     is not exploitable.
//   - The core enablement edges belief propagates along (ADR-0029 §7):
//     reachability (RESOLVES_TO — a subdomain resolves to a reachable host),
//     credential-grants (ISSUED — a run issues a credential),
//     trust (DELEGATED_TO — a run delegates to a sub-run), and
//     runs-service -> affects (RUNS_SERVICE, AFFECTS — a port runs a
//     service, and a finding affects the asset it was found on).
//
// A Domain Pack extends this schema — more belief-bearing node types (e.g.
// Finding, technique, mission per the ADR), more variables, more enablement
// edges — through the identical RegisterExtension seam, under its own name.
// This function's result never changes shape at runtime; discovery (#274)
// and promotion (#281) are how a Pack's OWN extension grows over time.
func SeedBeliefSchemaExtension() BeliefSchemaExtension {
	return BeliefSchemaExtension{
		Nodes: []NodeBeliefSchema{
			{
				NodeType: "Host",
				Variables: []BeliefVariable{
					{Name: "reachable"},
					{Name: "exploitable", DependsOn: []string{"reachable"}},
					{Name: "juicy", DependsOn: []string{"exploitable"}},
				},
			},
		},
		EnablementEdges: []string{
			"RESOLVES_TO",  // reachability
			"ISSUED",       // credential-grants
			"DELEGATED_TO", // trust
			"RUNS_SERVICE", // runs-service
			"AFFECTS",      // ...-> affects
		},
	}
}

// RegisterCoreBeliefSchemaSeed registers SeedBeliefSchemaExtension() with reg
// under the canonical core extension name. Call this once at startup,
// alongside Loader.LoadCore for the taxonomy Reasoner, before any Domain Pack
// registers its own belief schema extension.
func RegisterCoreBeliefSchemaSeed(reg *BeliefSchemaRegistry) error {
	return reg.RegisterExtension(coreBeliefSchemaExtensionName, SeedBeliefSchemaExtension())
}
