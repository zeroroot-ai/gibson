// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

// catalog_main_pack.go: the platform's seed "main" Domain Pack (ADR-0133's
// "the seed main pack is default-off", gibson#382, epic #376).
//
// MainDomainPack is a skeleton, not a fully-fleshed vertical: a small,
// representative set of technique -> CEL predicate bindings, plus the
// taxonomy structure they reference, curated by the platform owner
// (Visibility public — free, like every pack). It exists so the catalog
// gibson#381 built the enablement mechanism for is non-empty from the first
// daemon that ships it, and so EnableDomainPack has real, compiling content
// to fold into a tenant's World end to end.
//
// The pack ships default-off (ADR-0133): registering it in
// DomainPackCatalog makes it visible and enable-able, never enabled. A
// fresh tenant's brain.Engine.DomainPacks() starts empty regardless of what
// the catalog carries — DomainPackEnabled is the only thing that ever adds
// to it (see DomainPackService.EnableDomainPack) — so with MainDomainPack
// off, none of its Predicates are bound to any tenant's settlement path: no
// bet settles TRUE by proof against them. That is the intended default.

// MainDomainPackName is the catalog name of the platform's seed pack.
const MainDomainPackName = "main"

// MainDomainPack returns the platform's seed catalog pack: a skeleton set of
// predicate bindings spanning a few of the platform's core technique
// categories (types.TechniqueType — prompt_injection, reconnaissance,
// extraction), plus the small taxonomy structure they assume. Every
// predicate expression is plain CEL text, valid against the gibson-owned
// environment (internal/engine/settlement/celenv.NewEnv) — this package
// never compiles or type-checks it (ADR-0131 draws that line at
// celenv, strictly after DomainPack.Validate has already accepted the text
// here as well-formed).
//
// MainDomainPack returns a fresh value on every call: a caller that mutates
// the result (e.g. NewDomainPackCatalog's own defensive copies via List)
// never corrupts a shared instance.
func MainDomainPack() DomainPack {
	return DomainPack{
		Name:       MainDomainPackName,
		Version:    1,
		Author:     "zeroroot",
		Visibility: PackVisibilityPublic,

		// A minimal structural seed on top of the platform's own core
		// taxonomy (ADR-0133: "Importing a Pack layers these onto the
		// receiving install's own core, never replacing it"): the node/edge
		// shape the reconnaissance predicate below assumes evidence was
		// gathered about.
		TaxonomyNodeLabels:        []string{"WebEndpoint"},
		TaxonomyRelationshipTypes: []string{"EXPOSES"},

		// The written key form of each node label (gibson#484). A web endpoint
		// is identified by its URL — unique by construction, so two producers of
		// one endpoint merge on the same node instead of splitting it.
		TaxonomyNodeIdentity: map[string]string{"WebEndpoint": "url"},

		// A skeleton, representative set of technique -> CEL bindings —
		// enough to prove the enable path end to end, not a fully-fleshed
		// vertical (gibson#382 scope). Keyed by ValidIdentifier-shaped
		// technique names (ADR-0135); each references only the "evidence"
		// variable and the curated helper catalog celenv.NewEnv declares.
		Predicates: map[string]string{
			// reconnaissance: proof that some recorded HTTP exchange reached
			// a live, responding endpoint.
			"unauthenticated_endpoint_exposed": `evidence.exists(e, httpStatus(e) == 200)`,

			// extraction: proof that recorded evidence text contains what
			// reads like a disclosed credential (an API key, password, or
			// secret assigned to a value).
			"credential_disclosure_detected": `evidence.exists(e, regexMatch(evidenceText(e), "(?i)(api[_-]?key|password|secret)\\s*[:=]\\s*\\S+"))`,

			// prompt_injection: proof that the agent's own marker-of-control
			// (planted before the run, per markerPresent's "proof of
			// control, not damage" contract) turned up in what came back.
			"prompt_injection_marker_present": `markerPresent(evidence, "SYSTEM_PROMPT_LEAKED")`,
		},

		// The fine-grained techniques of this pack, each with the core
		// category that it rolls up to (ADR-0135). Each predicate above is
		// bound to one of them.
		Techniques: map[string]string{
			"unauthenticated_endpoint_exposed": "reconnaissance",
			"credential_disclosure_detected":   "extraction",
			"prompt_injection_marker_present":  "prompt_injection",
		},

		// The pack makes a web endpoint bear belief (ADR-0129): an endpoint
		// that answers is reachable, and a reachable endpoint can be
		// exploitable. EXPOSES is the edge of this pack from a host to its
		// endpoint, and it feeds "reachable".
		BeliefSchema: &BeliefSchemaExtension{
			Nodes: []NodeBeliefSchema{{
				NodeType: "WebEndpoint",
				Variables: []BeliefVariable{
					{Name: "reachable"},
					{Name: "exploitable", DependsOn: []string{"reachable"}},
				},
			}},
			EnablementEdges: []EnablementEdgeSpec{
				{RelType: "EXPOSES", TargetVariable: "reachable"},
			},
		},

		// Each predicate above reads evidence of a request the target already
		// answers. None of them needs a change on the target, so the pack
		// states all three as non-destructive (ADR-0132).
		NonDestructivePredicates: []string{
			"credential_disclosure_detected",
			"prompt_injection_marker_present",
			"unauthenticated_endpoint_exposed",
		},
	}
}
