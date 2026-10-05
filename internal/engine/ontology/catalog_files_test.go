// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mainPack returns the main pack from the embedded catalog.
func mainPack(t *testing.T) DomainPack {
	t.Helper()
	p, ok := EmbeddedPack(MainDomainPackName)
	require.True(t, ok, "the embedded catalog must hold the main pack")
	return p
}

// TestEmbeddedMainPack_IsTheFormerGoLiteral proves that the data file has
// the same content as the Go literal that it replaces (gibson#710).
// wantMainPack is that literal, kept here as the expected value.
func TestEmbeddedMainPack_IsTheFormerGoLiteral(t *testing.T) {
	assert.Equal(t, wantMainPack(), mainPack(t))
}

// TestLoadCatalog_ASecondPackNeedsNoGoChange: a second file is a second
// pack.
func TestLoadCatalog_ASecondPackNeedsNoGoChange(t *testing.T) {
	main, err := embeddedPackFiles.ReadFile("packs/main.json")
	require.NoError(t, err)
	fsys := fstest.MapFS{
		"packs/main.json": {Data: main},
		"packs/web.json":  {Data: []byte(`{"name":"web","version":2,"predicates":{"t1":"true"}}`)},
	}
	c, err := LoadCatalog(fsys)
	require.NoError(t, err)
	names := make([]string, 0, 2)
	for _, p := range c.List() {
		names = append(names, p.Name)
	}
	assert.Equal(t, []string{"main", "web"}, names)
	web, ok := c.Get("web")
	require.True(t, ok)
	assert.Equal(t, 2, web.Version)
}

func TestLoadCatalog_Refusals(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"no file":          {map[string]string{}, "no catalog pack file"},
		"bad JSON":         {map[string]string{"packs/a.json": `{"name":`}, "packs/a.json"},
		"unknown field":    {map[string]string{"packs/a.json": `{"name":"a","predicate":{}}`}, "unknown field"},
		"two documents":    {map[string]string{"packs/a.json": `{"name":"a"} {"name":"a"}`}, "more than one"},
		"name is not file": {map[string]string{"packs/a.json": `{"name":"b"}`}, `want "a"`},
		"invalid pack":     {map[string]string{"packs/a.json": `{"name":"a","taxonomy_node_labels":["bad label"]}`}, `catalog pack "a"`},
		"bad technique":    {map[string]string{"packs/a.json": `{"name":"a","techniques":{"t":"no_such"}}`}, "not admitted"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for f, body := range tc.files {
				fsys[f] = &fstest.MapFile{Data: []byte(body)}
			}
			_, err := LoadCatalog(fsys)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// TestLoadCatalog_RefusesAFileItCannotRead: a pack path that is a
// directory cannot be read, and LoadCatalog names the path.
func TestLoadCatalog_RefusesAFileItCannotRead(t *testing.T) {
	fsys := fstest.MapFS{"packs/a.json/inner": {Data: []byte(`{}`)}}
	_, err := LoadCatalog(fsys)
	require.ErrorContains(t, err, "read catalog pack file packs/a.json")
}

// TestNewCheckedCatalog_RefusesADuplicateName: two packs with one name
// are an error, not a panic.
func TestNewCheckedCatalog_RefusesADuplicateName(t *testing.T) {
	_, err := newCheckedCatalog([]DomainPack{{Name: "a"}, {Name: "a"}})
	require.ErrorContains(t, err, "duplicate name")
}

// TestEmbeddedCatalog_EveryFileLoads: each embedded pack file loads and
// validates. This is the check that keeps the start-time panic of
// EmbeddedCatalog out of a release.
func TestEmbeddedCatalog_EveryFileLoads(t *testing.T) {
	c, err := LoadCatalog(embeddedPackFiles)
	require.NoError(t, err)
	assert.NotEmpty(t, c.List())
}

func wantMainPack() DomainPack {
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
		BeliefSchema: BeliefSchemaExtension{
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
