// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mainPack returns the main pack from the embedded catalog.
func mainPack(t *testing.T) DomainPack {
	t.Helper()
	p, ok := EmbeddedCatalog().Get(MainDomainPackName)
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
		"packs/web.json": {Data: []byte(
			`{"name":"web","version":2,"predicates":{"t1":"true"},"techniques":{"t1":"reconnaissance"}}`)},
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
		"predicate outside the hierarchy": {
			map[string]string{"packs/a.json": `{"name":"a","predicates":{"no_such_technique":"true"}}`},
			"not a technique of the hierarchy",
		},
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
			"credential_disclosure_detected": `evidence.exists(e, regexMatch(evidenceText(e), "(?i)(api[_-]?key|password|secret)\\s*[:=]\\s*\\S+"))`,
			"node_token_readable":            `evidence.exists(e, regexMatch(evidenceText(e), r'/var/lib/kubelet/pods/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/volumes/kubernetes\.io~projected/') && regexMatch(evidenceText(e), r'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'))`,
			"privileged_container_detected":  `evidence.exists(e, regexMatch(evidenceText(e), r'(?m)^CapEff:\s*0*[0-9a-f]?f{9,}\s*$'))`,
			"rbac_write_access_proven":       `evidence.exists(e, httpStatus(e) == 201 && regexMatch(evidenceText(e), r'\\?"kind\\?"\s*:\s*\\?"ConfigMap\\?"') && regexMatch(evidenceText(e), r'\\?"name\\?"\s*:\s*\\?"gibson-proof-[a-z0-9]+\\?"'))`,
			"unauthenticated_endpoint_exposed": `((evidence.exists(q, q.type == "http_request" && type(q.content) == map && "url" in q.content && typ` +
				`e(q.content.url) == string && regexMatch(q.content.url, r'^https?://[^/]+/(admin|internal|management` +
				`|manage|actuator|debug)(/|\?|$)') && !("headers" in q.content && type(q.content.headers) == map && (` +
				`"authorization" in q.content.headers || "Authorization" in q.content.headers || "cookie" in q.conten` +
				`t.headers || "Cookie" in q.content.headers))) && evidence.exists(r, r.type == "http_response" && htt` +
				`pStatus(r) == 200 && regexMatch(evidenceText(r), r'^\s*[\{\[]\s*\"') && !regexMatch(evidenceText(r),` +
				` r'(?i)(<form|<input|type\s*=\s*.?password|\"(login|signin|sign_in|redirect)\"\s*:)'))) || evidence.` +
				`exists(e, e.type == "log" && httpStatus(e) == 200 && type(jsonPath(evidenceText(e), "url")) == strin` +
				`g && regexMatch(jsonPath(evidenceText(e), "url"), r'^https?://[^/]+/(admin|internal|management|manag` +
				`e|actuator|debug)(/|\?|$)') && type(jsonPath(evidenceText(e), "body")) == string && regexMatch(jsonP` +
				`ath(evidenceText(e), "body"), r'^\s*[\{\[]\s*\"') && !regexMatch(jsonPath(evidenceText(e), "body"), ` +
				`r'(?i)(<form|<input|type\s*=\s*.?password|\"(login|signin|sign_in|redirect)\"\s*:)'))) && !evidence.` +
				`exists(x, httpStatus(x) >= 300 && httpStatus(x) < 400)`,
		},

		// The fine-grained techniques of this pack, each with the core
		// category that it rolls up to (ADR-0135). Each predicate above is
		// bound to one of them.
		Techniques: map[string]string{
			"credential_disclosure_detected":   "credential_access",
			"node_token_readable":              "credential_access",
			"privileged_container_detected":    "privilege_escalation",
			"rbac_write_access_proven":         "privilege_escalation",
			"unauthenticated_endpoint_exposed": "initial_access",
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

		// The predicates below read evidence and change nothing on the target.
		// The predicate rbac_write_access_proven is not in this list: its proof
		// writes one object to the target, so it is destructive (ADR-0132).
		NonDestructivePredicates: []string{
			"credential_disclosure_detected",
			"node_token_readable",
			"privileged_container_detected",
			"unauthenticated_endpoint_exposed",
		},
	}
}

// TestLoadCatalog_RulesFile: a rules file adds its mapping rules to the pack
// of the same name.
func TestLoadCatalog_RulesFile(t *testing.T) {
	pack := `{"name":"fw","controls":[{"id":"ac-2","title":"Account Management","family":"ac","family_title":"Access Control"}]}`
	rules := `{"mapping_rules":[{"control_id":"ac-2","expression":"true"}]}`
	t.Run("rules join the pack", func(t *testing.T) {
		c, err := LoadCatalog(fstest.MapFS{
			"packs/fw.json":       {Data: []byte(pack)},
			"packs/fw.rules.json": {Data: []byte(rules)},
		})
		require.NoError(t, err)
		p, ok := c.Get("fw")
		require.True(t, ok)
		require.Len(t, p.MappingRules, 1)
		withRule, total := p.RuleCoverage()
		assert.Equal(t, 1, withRule)
		assert.Equal(t, 1, total)
	})
	refusals := map[string]struct {
		files map[string]string
		want  string
	}{
		"a rules file with no pack": {map[string]string{
			"packs/fw.json": pack, "packs/other.rules.json": rules,
		}, "has no pack file"},
		"rules in two places": {map[string]string{
			"packs/fw.json": `{"name":"fw","controls":[{"id":"ac-2","title":"t","family":"ac","family_title":"t"}],` +
				`"mapping_rules":[{"control_id":"ac-2","expression":"true"}]}`,
			"packs/fw.rules.json": rules,
		}, "in its pack file and in"},
		"an unknown field": {map[string]string{
			"packs/fw.json": pack, "packs/fw.rules.json": `{"rules":[]}`,
		}, "unknown field"},
		"a rule for a control that the pack does not have": {map[string]string{
			"packs/fw.json": pack, "packs/fw.rules.json": `{"mapping_rules":[{"control_id":"ac-3","expression":"true"}]}`,
		}, "not a control of the pack"},
		"only a rules file": {map[string]string{"packs/fw.rules.json": rules}, "no catalog pack file"},
		"two rules documents": {map[string]string{
			"packs/fw.json": pack, "packs/fw.rules.json": rules + " " + rules,
		}, "more than one JSON document"},
		"a rules file that cannot be read": {map[string]string{
			"packs/fw.json": pack, "packs/fw.rules.json/inner": "{}",
		}, "read rules file packs/fw.rules.json"},
	}
	for name, tc := range refusals {
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

func TestValidate_Controls(t *testing.T) {
	ok := Control{ID: "ac-2", Title: "Account Management", Family: "ac", FamilyTitle: "Access Control"}
	require.NoError(t, (&DomainPack{Name: "p", Controls: []Control{ok}}).Validate())
	bad := map[string][]Control{
		"duplicate id":       {ok, ok},
		"bad id":             {{ID: "ac 2", Title: "t", Family: "ac", FamilyTitle: "t"}},
		"bad family":         {{ID: "ac-2", Title: "t", Family: "", FamilyTitle: "t"}},
		"empty title":        {{ID: "ac-2", Title: " ", Family: "ac", FamilyTitle: "t"}},
		"empty family title": {{ID: "ac-2", Title: "t", Family: "ac", FamilyTitle: ""}},
		"long title":         {{ID: "ac-2", Title: strings.Repeat("a", MaxControlTitleBytes+1), Family: "ac", FamilyTitle: "t"}},
	}
	for name, controls := range bad {
		t.Run(name, func(t *testing.T) {
			require.Error(t, (&DomainPack{Name: "p", Controls: controls}).Validate())
		})
	}
}
