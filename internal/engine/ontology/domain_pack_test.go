// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// -----------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------

func k8sVerticalExtension() sdkgraphrag.OntologyExtension {
	return sdkgraphrag.OntologyExtension{
		Prefixes: map[string]string{"k8s": "https://example.com/k8s#"},
		Hierarchies: []sdkgraphrag.HierarchyDef{
			{NodeType: "technology", Label: "k8s:Pod", SubClassOf: "k8s:Workload"},
		},
		IFPs: []sdkgraphrag.IFPDef{{NodeType: "technology", Property: "uid"}},
	}
}

// -----------------------------------------------------------------------
// Acceptance: a Pack captures the discovered taxonomy+ontology for a domain,
// versioned (criterion 1).
// -----------------------------------------------------------------------

func TestExportDomainPack_CapturesTaxonomyDiffOnly(t *testing.T) {
	base, err := taxonomy.New(1, []string{taxonomy.ObservationLabel, "Host"}, []string{"HAS_PORT"})
	require.NoError(t, err)
	now, err := taxonomy.New(2, []string{taxonomy.ObservationLabel, "Host", "Pod"}, []string{"HAS_PORT", "MANAGES"})
	require.NoError(t, err)

	r := NewReasoner(NewMetrics())

	pack, err := ExportDomainPack("k8s", 1, base, now, r)
	require.NoError(t, err)

	assert.Equal(t, "k8s", pack.Name)
	assert.Equal(t, 1, pack.Version)
	assert.Equal(t, []string{"Pod"}, pack.TaxonomyNodeLabels)
	assert.Equal(t, []string{"MANAGES"}, pack.TaxonomyRelationshipTypes)
}

func TestExportDomainPack_CapturesOntologyExcludingCore(t *testing.T) {
	base, err := taxonomy.New(1, []string{taxonomy.ObservationLabel}, nil)
	require.NoError(t, err)

	r := NewReasoner(NewMetrics())
	require.NoError(t, r.RegisterExtension("core", sdkgraphrag.OntologyExtension{
		Prefixes:    map[string]string{"soc2": "https://trust.aicpa.org/soc2#"},
		Hierarchies: []sdkgraphrag.HierarchyDef{{NodeType: "control", Label: "soc2:CC6"}},
	}))
	require.NoError(t, r.RegisterExtension("discovered/agent-1/abc123", k8sVerticalExtension()))

	pack, err := ExportDomainPack("k8s", 1, base, base, r, "core")
	require.NoError(t, err)

	require.Len(t, pack.Ontology, 1)
	assert.Equal(t, k8sVerticalExtension(), pack.Ontology["discovered/agent-1/abc123"])
}

// -----------------------------------------------------------------------
// Acceptance: a Pack carries no tenant secrets, verified (criterion 3).
// -----------------------------------------------------------------------

func TestDomainPack_Validate_AcceptsCleanPack(t *testing.T) {
	pack := &DomainPack{
		Name:                      "k8s",
		Version:                   1,
		TaxonomyNodeLabels:        []string{"Pod"},
		TaxonomyRelationshipTypes: []string{"MANAGES"},
		Ontology:                  map[string]sdkgraphrag.OntologyExtension{"discovered/x": k8sVerticalExtension()},
	}
	require.NoError(t, pack.Validate())
}

func TestDomainPack_Validate_RejectsInvalidTaxonomyLabel(t *testing.T) {
	pack := &DomainPack{
		Name:               "k8s",
		Version:            1,
		TaxonomyNodeLabels: []string{"Pod`; DETACH DELETE n; //"},
	}
	require.Error(t, pack.Validate())
}

func TestDomainPack_Validate_RejectsRawTriples(t *testing.T) {
	pack := &DomainPack{
		Name:    "k8s",
		Version: 1,
		Ontology: map[string]sdkgraphrag.OntologyExtension{
			"discovered/x": {RawTriples: []byte("some raw turtle payload, unvalidated")},
		},
	}
	err := pack.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RawTriples")
}

func TestExportDomainPack_FailsOnRawTriplesExtension(t *testing.T) {
	base, err := taxonomy.New(1, []string{taxonomy.ObservationLabel}, nil)
	require.NoError(t, err)

	r := NewReasoner(NewMetrics())
	require.NoError(t, r.RegisterExtension("discovered/x", sdkgraphrag.OntologyExtension{
		RawTriples: []byte("unvalidated turtle"),
	}))

	pack, err := ExportDomainPack("k8s", 1, base, base, r)
	require.Error(t, err)
	assert.Nil(t, pack)
}

// -----------------------------------------------------------------------
// Acceptance: a Pack is exportable and importable into another install
// (criterion 2), and importing seeds a new environment while discovery
// extends it (criterion 4).
// -----------------------------------------------------------------------

func TestDomainPack_Import_SeedsNewEnvironment(t *testing.T) {
	freshTax, err := taxonomy.New(1, []string{taxonomy.ObservationLabel}, nil)
	require.NoError(t, err)
	freshReasoner := NewReasoner(NewMetrics())

	pack := &DomainPack{
		Name:                      "k8s",
		Version:                   1,
		TaxonomyNodeLabels:        []string{"Pod"},
		TaxonomyRelationshipTypes: []string{"MANAGES"},
		Ontology:                  map[string]sdkgraphrag.OntologyExtension{"discovered/x": k8sVerticalExtension()},
	}

	newTax, err := pack.Import(freshTax, freshReasoner)
	require.NoError(t, err)

	assert.True(t, newTax.ClassifyNode("Pod").InTaxonomy)
	assert.True(t, newTax.ClassifyRelationship("MANAGES").InTaxonomy)
	assert.Contains(t, freshReasoner.Ancestors("k8s:Pod"), "k8s:Workload")
	assert.Equal(t, []string{"uid"}, freshReasoner.IFPsForType("technology"))
}

func TestDomainPack_Import_RejectsUnsafeOntologyContentViaExistingGate(t *testing.T) {
	// A corrupted/malicious pack that would introduce a cycle against the
	// receiving install's OWN existing ontology is still refused at import
	// time: importing never bypasses RegisterExtension's own safety checks.
	tax, err := taxonomy.New(1, []string{taxonomy.ObservationLabel}, nil)
	require.NoError(t, err)
	r := NewReasoner(NewMetrics())
	require.NoError(t, r.RegisterExtension("existing", sdkgraphrag.OntologyExtension{
		Prefixes:    map[string]string{"k8s": "https://example.com/k8s#"},
		Hierarchies: []sdkgraphrag.HierarchyDef{{NodeType: "technology", Label: "k8s:Workload", SubClassOf: "k8s:Pod"}},
	}))

	pack := &DomainPack{
		Name:     "k8s",
		Version:  1,
		Ontology: map[string]sdkgraphrag.OntologyExtension{"discovered/x": k8sVerticalExtension()},
	}

	_, err = pack.Import(tax, r)
	require.Error(t, err)
	var cycleErr *CycleError
	require.ErrorAs(t, err, &cycleErr)
}

func TestDomainPack_Import_IsIdempotentOnReimport(t *testing.T) {
	tax, err := taxonomy.New(1, []string{taxonomy.ObservationLabel}, nil)
	require.NoError(t, err)
	r := NewReasoner(NewMetrics())

	pack := &DomainPack{
		Name:               "k8s",
		Version:            1,
		TaxonomyNodeLabels: []string{"Pod"},
		Ontology:           map[string]sdkgraphrag.OntologyExtension{"discovered/x": k8sVerticalExtension()},
	}

	tax1, err := pack.Import(tax, r)
	require.NoError(t, err)
	tax2, err := pack.Import(tax1, r)
	require.NoError(t, err)

	assert.Equal(t, tax1.NodeLabels(), tax2.NodeLabels())
}

func TestDomainPack_ExportImport_RoundTripsThroughJSON(t *testing.T) {
	original := &DomainPack{
		Name:                      "k8s",
		Version:                   3,
		TaxonomyNodeLabels:        []string{"Pod"},
		TaxonomyRelationshipTypes: []string{"MANAGES"},
		Ontology:                  map[string]sdkgraphrag.OntologyExtension{"discovered/x": k8sVerticalExtension()},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var roundTripped DomainPack
	require.NoError(t, json.Unmarshal(data, &roundTripped))

	assert.Equal(t, original, &roundTripped)

	tax, err := taxonomy.New(1, []string{taxonomy.ObservationLabel}, nil)
	require.NoError(t, err)
	r := NewReasoner(NewMetrics())
	_, err = roundTripped.Import(tax, r)
	require.NoError(t, err)
	assert.Contains(t, r.Ancestors("k8s:Pod"), "k8s:Workload")
}

func TestDomainPack_ImportThenExportAgain_DiscoveryExtendsThePack(t *testing.T) {
	// Import v1 of a pack into a fresh environment, simulate ongoing
	// discovery (gibson#274/#281) on top of it, then export v2 and assert it
	// contains the union of the seed content and what discovery added.
	freshTax, err := taxonomy.New(1, []string{taxonomy.ObservationLabel}, nil)
	require.NoError(t, err)
	freshReasoner := NewReasoner(NewMetrics())

	v1 := &DomainPack{
		Name:               "k8s",
		Version:            1,
		TaxonomyNodeLabels: []string{"Pod"},
		Ontology:           map[string]sdkgraphrag.OntologyExtension{"discovered/x": k8sVerticalExtension()},
	}
	seededTax, err := v1.Import(freshTax, freshReasoner)
	require.NoError(t, err)

	// Discovery extends the imported environment (gibson#281's gate).
	gate := taxonomy.NewPromotionGate(seededTax)
	for range taxonomy.MinRecurrenceForSettlement {
		gate.Observe(taxonomy.ProposedNodeLabel, "Service")
	}
	require.NoError(t, gate.Confirm(taxonomy.ProposedNodeLabel, "Service", "reviewer-1"))
	discoveredTax, err := gate.Promote(taxonomy.ProposedNodeLabel, "Service")
	require.NoError(t, err)

	// And gibson#274's ontology discovery gate.
	out := ProposeExtension(freshReasoner, StructuralHypothesis{
		Proposer: "agent-2",
		Claim:    "services should subclass k8s:Workload too",
		Extension: sdkgraphrag.OntologyExtension{
			Prefixes:    map[string]string{"k8s": "https://example.com/k8s#"},
			Hierarchies: []sdkgraphrag.HierarchyDef{{NodeType: "technology", Label: "k8s:Service", SubClassOf: "k8s:Workload"}},
		},
	})
	require.True(t, out.Accepted)

	v2, err := ExportDomainPack("k8s", 2, freshTax, discoveredTax, freshReasoner)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"Pod", "Service"}, v2.TaxonomyNodeLabels)
	assert.Contains(t, v2.Ontology, "discovered/x")
	assert.Contains(t, v2.Ontology, out.ExtensionName)
	assert.Equal(t, 2, v2.Version)
}

// -----------------------------------------------------------------------
// Validate's relationship-type branch, and Import's two error-wrapping
// branches (an already-invalid pack, and a taxonomy.New failure after
// Ontology registration already succeeded) were 0%-covered: every earlier
// test exercised the node-label side of Validate, and every Import test
// used an already-valid pack against a taxonomy.New call that succeeds.
// -----------------------------------------------------------------------

func TestDomainPack_Validate_RejectsInvalidRelationshipType(t *testing.T) {
	pack := &DomainPack{
		Name:                      "k8s",
		Version:                   1,
		TaxonomyRelationshipTypes: []string{"MANAGES`; DETACH DELETE n; //"},
	}
	err := pack.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "taxonomy relationship type")
}

func TestDomainPack_Import_RefusesAnAlreadyInvalidPack(t *testing.T) {
	tax, err := taxonomy.New(1, []string{taxonomy.ObservationLabel}, nil)
	require.NoError(t, err)
	r := NewReasoner(NewMetrics())

	pack := &DomainPack{
		Name:               "k8s",
		Version:            1,
		TaxonomyNodeLabels: []string{"Pod`; DETACH DELETE n; //"},
	}

	newTax, err := pack.Import(tax, r)
	require.Error(t, err)
	assert.Nil(t, newTax)
	assert.Contains(t, err.Error(), "import domain pack")
}

func TestDomainPack_Import_WrapsATaxonomyConstructionFailure(t *testing.T) {
	// A taxonomyBase already at the maximum representable version makes
	// taxonomyBase.Version()+1 overflow to a non-positive value, which
	// taxonomy.New refuses — proving Import's final error-wrapping branch
	// fires even after the pack's own ontology extensions already
	// registered successfully (so a partial-apply is visible: the
	// extension lands in reasoner, but the caller still gets an error and
	// no taxonomy.Registry back).
	overflowingBase, err := taxonomy.New(math.MaxInt, []string{taxonomy.ObservationLabel}, nil)
	require.NoError(t, err)
	r := NewReasoner(NewMetrics())

	pack := &DomainPack{
		Name:               "k8s",
		Version:            1,
		TaxonomyNodeLabels: []string{"Pod"},
		Ontology:           map[string]sdkgraphrag.OntologyExtension{"discovered/x": k8sVerticalExtension()},
	}

	newTax, err := pack.Import(overflowingBase, r)
	require.Error(t, err)
	assert.Nil(t, newTax)
	assert.Contains(t, err.Error(), "taxonomy")
	// The ontology side already registered before the taxonomy step failed.
	assert.Contains(t, r.Ancestors("k8s:Pod"), "k8s:Workload")
}
