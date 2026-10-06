// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

// belief_schema_seed.go is the SEED belief-PRM schema (ADR-0129): it
// replaces the hardcoded {reachable, exploitable, juicy} per-Host belief
// field (ADR-0129, internal/engine/brain/belief.go) with the same three
// variables, expressed as declarative schema instead of Go structs, so the
// belief engine (gibson#275/#276) can generalise beyond Host without a code
// change to this package.
//
// coreBeliefSchemaExtensionName mirrors ontology.Loader's "core/<file>"
// naming convention for taxonomy YAML extensions (loader.go).
const coreBeliefSchemaExtensionName = "core/belief-schema"

// HostNodeType is the node type of a host in the core belief schema. The
// belief trainer fits the in-node strengths of this node type from its host
// rows (gibson#720).
const HostNodeType = "Host"

// SeedBeliefSchemaExtension returns the seed belief-PRM schema:
//
//   - Host is belief-bearing with the three seed variables from ADR-0129,
//     wired as a small dependency chain (reachable -> exploitable -> juicy)
//     matching the funnel the pre-PRM belief field already encodes: a target
//     cannot be exploitable if it is not reachable, and cannot be juicy if it
//     is not exploitable.
//   - The core enablement edges belief propagates along (ADR-0129), each
//     naming the belief variable it feeds on its destination node (ADR-0137
//     — structure only; the noisy-OR strength each contributes is
//     a learned Beta posterior, cold-started at the uninformative prior,
//     never authored here):
//   - RESOLVES_TO feeds "reachable" (reachability — a subdomain resolving to
//     a host is what makes it reachable at all).
//   - DELEGATED_TO feeds "reachable" (trust — a run delegating to a sub-run
//     extends which further hosts that trust boundary makes reachable).
//   - ISSUED feeds "exploitable" (credential-grants — a run issuing a
//     credential is a usable path onto whatever it grants access to).
//   - RUNS_SERVICE feeds "exploitable" (runs-service — a running,
//     network-exposed service is attack surface, not just reachability).
//   - AFFECTS feeds "juicy" (a finding affecting an asset is what marks the
//     asset a valuable/vulnerable target, the funnel's terminal variable).
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
				NodeType: HostNodeType,
				Variables: []BeliefVariable{
					{Name: "reachable"},
					{Name: "exploitable", DependsOn: []string{"reachable"}},
					{Name: "juicy", DependsOn: []string{"exploitable"}},
				},
			},
		},
		EnablementEdges: []EnablementEdgeSpec{
			{RelType: "RESOLVES_TO", TargetVariable: "reachable"},    // reachability
			{RelType: "DELEGATED_TO", TargetVariable: "reachable"},   // trust
			{RelType: "ISSUED", TargetVariable: "exploitable"},       // credential-grants
			{RelType: "RUNS_SERVICE", TargetVariable: "exploitable"}, // runs-service
			{RelType: "AFFECTS", TargetVariable: "juicy"},            // ...-> affects
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
