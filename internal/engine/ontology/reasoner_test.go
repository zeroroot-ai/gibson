package ontology

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// -----------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------

// coreExt is a fixture ontology describing a control hierarchy:
//
//	soc2:CC6 (root)
//	  └─ soc2:CC6.1
//	       └─ soc2:CC6.1.1
//	  └─ soc2:CC6.2
//	mitre:T1 (root)
//	  └─ mitre:T1.001
//	  └─ mitre:T1.002
var coreExt = sdkgraphrag.OntologyExtension{
	Prefixes: map[string]string{
		"soc2":  "https://trust.aicpa.org/soc2#",
		"mitre": "https://attack.mitre.org/techniques/",
	},
	Hierarchies: []sdkgraphrag.HierarchyDef{
		{NodeType: "control", Label: "soc2:CC6"},
		{NodeType: "control", Label: "soc2:CC6.1", SubClassOf: "soc2:CC6"},
		{NodeType: "control", Label: "soc2:CC6.1.1", SubClassOf: "soc2:CC6.1"},
		{NodeType: "control", Label: "soc2:CC6.2", SubClassOf: "soc2:CC6"},
		{NodeType: "technique", Label: "mitre:T1"},
		{NodeType: "technique", Label: "mitre:T1.001", SubClassOf: "mitre:T1"},
		{NodeType: "technique", Label: "mitre:T1.002", SubClassOf: "mitre:T1"},
	},
	Equivalences: [][2]string{
		{"soc2:CC6.1", "mitre:T1.001"},
	},
	IFPs: []sdkgraphrag.IFPDef{
		{NodeType: "control", Property: "control_id"},
		{NodeType: "host", Property: "ip"},
		{NodeType: "host", Property: "hostname"},
	},
}

// extExt is a fixture extension extending the core with a deeper level.
var extExt = sdkgraphrag.OntologyExtension{
	Prefixes: map[string]string{
		"soc2": "https://trust.aicpa.org/soc2#",
		"ext":  "https://example.com/ext#",
	},
	Hierarchies: []sdkgraphrag.HierarchyDef{
		{NodeType: "control", Label: "soc2:CC6.3", SubClassOf: "soc2:CC6"},
		{NodeType: "control", Label: "ext:Custom1", SubClassOf: "soc2:CC6.3"},
	},
	IFPs: []sdkgraphrag.IFPDef{
		{NodeType: "control", Property: "ext_ref"},
	},
}

// newTestReasoner returns a Reasoner pre-loaded with coreExt.
func newTestReasoner(t *testing.T) *Reasoner {
	t.Helper()
	r := NewReasoner(NewMetrics())
	require.NoError(t, r.RegisterExtension("core", coreExt))
	return r
}

// -----------------------------------------------------------------------
// Ancestor / Descendant tests
// -----------------------------------------------------------------------

func TestReasoner_Ancestors_DirectParent(t *testing.T) {
	r := newTestReasoner(t)
	ancs := r.Ancestors("soc2:CC6.1")
	assert.Contains(t, ancs, "soc2:CC6")
}

func TestReasoner_Ancestors_TransitiveDepth(t *testing.T) {
	r := newTestReasoner(t)
	// CC6.1.1 → CC6.1 → CC6
	ancs := r.Ancestors("soc2:CC6.1.1")
	assert.Contains(t, ancs, "soc2:CC6.1", "should contain direct parent")
	assert.Contains(t, ancs, "soc2:CC6", "should contain grandparent")
}

func TestReasoner_Ancestors_Root(t *testing.T) {
	r := newTestReasoner(t)
	// Root nodes have no ancestors.
	ancs := r.Ancestors("soc2:CC6")
	assert.Empty(t, ancs)
}

func TestReasoner_Ancestors_Unknown(t *testing.T) {
	r := newTestReasoner(t)
	ancs := r.Ancestors("soc2:UNKNOWN")
	assert.Empty(t, ancs)
}

func TestReasoner_Descendants_Direct(t *testing.T) {
	r := newTestReasoner(t)
	desc := r.Descendants("soc2:CC6")
	assert.Contains(t, desc, "soc2:CC6.1")
	assert.Contains(t, desc, "soc2:CC6.2")
	assert.Contains(t, desc, "soc2:CC6.1.1", "should include grandchildren")
}

func TestReasoner_Descendants_Leaf(t *testing.T) {
	r := newTestReasoner(t)
	desc := r.Descendants("soc2:CC6.1.1")
	assert.Empty(t, desc)
}

func TestReasoner_Descendants_Unknown(t *testing.T) {
	r := newTestReasoner(t)
	desc := r.Descendants("soc2:UNKNOWN")
	assert.Empty(t, desc)
}

func TestReasoner_IsSubclassOf(t *testing.T) {
	r := newTestReasoner(t)
	tests := []struct {
		child, parent string
		want          bool
	}{
		{"soc2:CC6.1", "soc2:CC6", true},
		{"soc2:CC6.1.1", "soc2:CC6", true},
		{"soc2:CC6.1.1", "soc2:CC6.1", true},
		{"soc2:CC6", "soc2:CC6.1", false}, // parent is not subclass of child
		{"soc2:CC6", "soc2:CC6", false},   // reflexive returns false per spec
		{"soc2:CC6", "soc2:UNKNOWN", false},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_subclass_of_%s", tc.child, tc.parent), func(t *testing.T) {
			assert.Equal(t, tc.want, r.IsSubclassOf(tc.child, tc.parent))
		})
	}
}

// -----------------------------------------------------------------------
// Wide fixture: deep+wide ancestor/descendant correctness
// -----------------------------------------------------------------------

func TestReasoner_DeepWideHierarchy(t *testing.T) {
	// Build a 3-level wide hierarchy: root → 5 children, each with 3 grandchildren.
	prefixes := map[string]string{"test": "https://test.example/"}
	hier := []sdkgraphrag.HierarchyDef{
		{NodeType: "n", Label: "test:Root"},
	}
	for i := 0; i < 5; i++ {
		child := fmt.Sprintf("test:L1-%d", i)
		hier = append(hier, sdkgraphrag.HierarchyDef{NodeType: "n", Label: child, SubClassOf: "test:Root"})
		for j := 0; j < 3; j++ {
			grandChild := fmt.Sprintf("test:L2-%d-%d", i, j)
			hier = append(hier, sdkgraphrag.HierarchyDef{NodeType: "n", Label: grandChild, SubClassOf: child})
		}
	}
	ext := sdkgraphrag.OntologyExtension{Prefixes: prefixes, Hierarchies: hier}

	r := NewReasoner(NewMetrics())
	require.NoError(t, r.RegisterExtension("test", ext))

	rootDesc := r.Descendants("test:Root")
	assert.Len(t, rootDesc, 5+15, "5 L1 children + 15 L2 grandchildren")

	for i := 0; i < 5; i++ {
		child := fmt.Sprintf("test:L1-%d", i)
		childDesc := r.Descendants(child)
		assert.Len(t, childDesc, 3, "each L1 node has 3 grandchildren")

		for j := 0; j < 3; j++ {
			grandChild := fmt.Sprintf("test:L2-%d-%d", i, j)
			ancs := r.Ancestors(grandChild)
			assert.Contains(t, ancs, child)
			assert.Contains(t, ancs, "test:Root")
			assert.True(t, r.IsSubclassOf(grandChild, "test:Root"))
			assert.True(t, r.IsSubclassOf(grandChild, child))
		}
	}
}

// -----------------------------------------------------------------------
// Equivalence tests
// -----------------------------------------------------------------------

func TestReasoner_Equivalents_Direct(t *testing.T) {
	r := newTestReasoner(t)
	// soc2:CC6.1 ≡ mitre:T1.001 (declared in coreExt)
	eq := r.Equivalents("soc2:CC6.1")
	assert.Contains(t, eq, "mitre:T1.001")
}

func TestReasoner_Equivalents_Symmetric(t *testing.T) {
	r := newTestReasoner(t)
	eq := r.Equivalents("mitre:T1.001")
	assert.Contains(t, eq, "soc2:CC6.1")
}

func TestReasoner_Equivalents_Transitive(t *testing.T) {
	// A≡B, B≡C → query A should return C.
	ext := sdkgraphrag.OntologyExtension{
		Prefixes: map[string]string{
			"a": "https://a.example/",
			"b": "https://b.example/",
			"c": "https://c.example/",
		},
		Equivalences: [][2]string{
			{"a:X", "b:Y"},
			{"b:Y", "c:Z"},
		},
	}
	r := NewReasoner(NewMetrics())
	require.NoError(t, r.RegisterExtension("chain", ext))

	eqA := r.Equivalents("a:X")
	assert.Contains(t, eqA, "b:Y")
	assert.Contains(t, eqA, "c:Z", "transitive equivalence: a:X should reach c:Z via b:Y")

	eqC := r.Equivalents("c:Z")
	assert.Contains(t, eqC, "a:X", "reverse direction must also be reachable")
}

func TestReasoner_Equivalents_Unknown(t *testing.T) {
	r := newTestReasoner(t)
	eq := r.Equivalents("soc2:UNKNOWN")
	assert.Empty(t, eq)
}

// -----------------------------------------------------------------------
// IFP tests
// -----------------------------------------------------------------------

func TestReasoner_IFPsForType(t *testing.T) {
	r := newTestReasoner(t)
	props := r.IFPsForType("control")
	assert.Contains(t, props, "control_id")

	hostProps := r.IFPsForType("host")
	assert.Contains(t, hostProps, "ip")
	assert.Contains(t, hostProps, "hostname")
}

func TestReasoner_IFPsForType_Unknown(t *testing.T) {
	r := newTestReasoner(t)
	props := r.IFPsForType("nonexistent_type")
	assert.Empty(t, props)
}

// -----------------------------------------------------------------------
// Extension registration / unregistration
// -----------------------------------------------------------------------

func TestReasoner_RegisterExtension_Merge(t *testing.T) {
	r := newTestReasoner(t) // has coreExt
	require.NoError(t, r.RegisterExtension("ext", extExt))

	// After merge: soc2:CC6 should now have CC6.3 and ext:Custom1 as descendants.
	desc := r.Descendants("soc2:CC6")
	assert.Contains(t, desc, "soc2:CC6.3")
	assert.Contains(t, desc, "ext:Custom1")
}

func TestReasoner_RegisterExtension_IFPMerge(t *testing.T) {
	r := newTestReasoner(t)
	require.NoError(t, r.RegisterExtension("ext", extExt))

	// extExt adds ext_ref IFP for "control"; existing "control_id" must still be present.
	props := r.IFPsForType("control")
	assert.Contains(t, props, "control_id")
	assert.Contains(t, props, "ext_ref")
}

func TestReasoner_RegisterExtension_BenignDuplicate(t *testing.T) {
	// Registering the same hierarchy triple twice → first-wins, no error.
	r := NewReasoner(NewMetrics())
	require.NoError(t, r.RegisterExtension("core", coreExt))
	// Re-register same extension under a different name — duplicate triples.
	dup := sdkgraphrag.OntologyExtension{
		Prefixes:    coreExt.Prefixes,
		Hierarchies: coreExt.Hierarchies, // identical triples
	}
	require.NoError(t, r.RegisterExtension("dup", dup), "benign duplicate must not error")
	// The hierarchy should still be correct.
	assert.True(t, r.IsSubclassOf("soc2:CC6.1", "soc2:CC6"))
}

func TestReasoner_RegisterExtension_CycleRejected(t *testing.T) {
	r := newTestReasoner(t)
	// Attempt to introduce a cycle: CC6 → CC6.1 (already exists) and CC6.1 → CC6.
	cycleExt := sdkgraphrag.OntologyExtension{
		Prefixes: map[string]string{"soc2": "https://trust.aicpa.org/soc2#"},
		Hierarchies: []sdkgraphrag.HierarchyDef{
			// CC6 is a subclass of CC6.1 — creates a cycle.
			{NodeType: "control", Label: "soc2:CC6", SubClassOf: "soc2:CC6.1"},
		},
	}
	err := r.RegisterExtension("cycle", cycleExt)
	require.Error(t, err)
	assert.True(t, isCycleError(err), "expected CycleError, got: %T %v", err, err)

	// State must be unchanged after rejection.
	assert.True(t, r.IsSubclassOf("soc2:CC6.1", "soc2:CC6"), "original hierarchy intact after cycle rejection")
	assert.False(t, r.IsSubclassOf("soc2:CC6", "soc2:CC6.1"), "cycle edge must not be committed")
}

func TestReasoner_RegisterExtension_UnknownPrefixRejected(t *testing.T) {
	r := NewReasoner(NewMetrics())
	badExt := sdkgraphrag.OntologyExtension{
		Prefixes: map[string]string{
			"soc2": "https://trust.aicpa.org/soc2#",
			// "mitre" prefix NOT declared
		},
		Hierarchies: []sdkgraphrag.HierarchyDef{
			{NodeType: "control", Label: "soc2:CC6"},
			{NodeType: "technique", Label: "mitre:T1"}, // unknown prefix
		},
	}
	err := r.RegisterExtension("bad", badExt)
	require.Error(t, err)
	assert.True(t, isUnknownPrefixError(err), "expected UnknownPrefixError, got: %T %v", err, err)
}

func TestReasoner_UnregisterExtension_Cleanup(t *testing.T) {
	r := newTestReasoner(t)
	require.NoError(t, r.RegisterExtension("ext", extExt))

	// Confirm ext IRIs are present.
	assert.Contains(t, r.Descendants("soc2:CC6"), "soc2:CC6.3")

	// Unregister.
	require.NoError(t, r.UnregisterExtension("ext"))

	// IRIs from extExt should be gone.
	desc := r.Descendants("soc2:CC6")
	assert.NotContains(t, desc, "soc2:CC6.3", "unregistered IRI should be removed")
	assert.NotContains(t, desc, "ext:Custom1", "unregistered IRI should be removed")

	// Core IRIs remain.
	assert.Contains(t, desc, "soc2:CC6.1", "core IRIs must survive unregister")
}

func TestReasoner_UnregisterExtension_NoOp(t *testing.T) {
	r := newTestReasoner(t)
	// Unregistering a nonexistent extension is a no-op.
	require.NoError(t, r.UnregisterExtension("nonexistent"))
}

// -----------------------------------------------------------------------
// Concurrency safety (tested with -race)
// -----------------------------------------------------------------------

func TestReasoner_ConcurrentReadsDuringRebuild(t *testing.T) {
	r := newTestReasoner(t)

	// Hammer reads while a goroutine does a register/unregister cycle.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			name := fmt.Sprintf("dyn-%d", i)
			ext := sdkgraphrag.OntologyExtension{
				Prefixes: map[string]string{"dyn": "https://dyn.example/"},
				Hierarchies: []sdkgraphrag.HierarchyDef{
					{NodeType: "n", Label: fmt.Sprintf("dyn:N%d", i)},
				},
			}
			_ = r.RegisterExtension(name, ext)
			_ = r.UnregisterExtension(name)
		}
	}()

	for {
		select {
		case <-done:
			return
		default:
			_ = r.Ancestors("soc2:CC6.1")
			_ = r.Descendants("soc2:CC6")
			_ = r.Equivalents("soc2:CC6.1")
			_ = r.IFPsForType("host")
		}
	}
}
