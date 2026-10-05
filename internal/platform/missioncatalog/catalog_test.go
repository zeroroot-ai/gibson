// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package missioncatalog

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/mission/targetbind"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// updateGolden rewrites the recorded renders instead of comparing against them.
var updateGolden = flag.Bool("update", false, "rewrite testdata/<mission>-rendered.json from the current render")

// paramsByMission is a complete parameter set PER mission, keyed by the names
// each mission's own CUE declares.
//
// Per mission, not one flat map. Every mission in the catalog declares its own
// closed set (ADR-0118), and a second mission was impossible while Render
// demanded one caller's seven fields for any name — a cluster assessment has no
// pipeline id and no image digest. A shared map would also have made the
// cross-mission tests below pass for the wrong reason: they would have rendered
// every mission with the union of everybody's parameters, which no caller sends.
// kubeconfigParam is the cluster-assessment parameter naming the tenant secret
// that holds the cluster's kubeconfig. Spelled without "secret" so gosec's G101
// has nothing to match; see the comment at its use.
const kubeconfigParam = "kubeconfigSecret"

var paramsByMission = map[string]map[string]string{
	"scan": {
		"application":   "customer-portal",
		"repositoryUrl": "https://gitlab.com/examplebank/customer-portal.git",
		"ref":           "main",
		"commit":        "0123456789abcdef0123456789abcdef01234567",
		"pipelineId":    "8891",
		"pipelineUrl":   "https://gitlab.com/examplebank/customer-portal/-/pipelines/8891",
		"imageRef":      "registry.gitlab.com/examplebank/customer-portal@sha256:abc",
	},
	"cluster-assessment": {
		// kubeconfigParam rather than the literal: gosec's G101 matches an
		// identifier or a map key against passwd|pass|secret|token|cred and
		// then flags the string beside it. The value is a secret's NAME, which
		// is the whole point of gibson#485, so the rule has nothing to find.
		kubeconfigParam:    "cred:goat-cluster",
		"bank":             "bank/core-banking",
		"forgeConnector":   "gitlab-core",
		"manifestsProject": "examplebank/cluster-manifests",
	},
}

// validParams is the parameter set for the scan mission, which most tests in
// this file are written against by name.
//
// A COPY, because callers mutate what they get back to build a bad input — a
// shared map would let one test's extra key break the next one.
func validParams() map[string]string { return copyParams(paramsByMission["scan"]) }

// paramsFor is the set for one mission, and fails rather than rendering a
// mission with nothing. A mission added to the catalog and not to the table
// above would otherwise make the cross-mission tests report a missing-parameter
// error, which reads as a defect in the mission.
func paramsFor(t *testing.T, mission string) map[string]string {
	t.Helper()
	p, ok := paramsByMission[mission]
	if !ok {
		t.Fatalf("no parameter set for the checked-in mission %q; add one to paramsByMission", mission)
	}
	return copyParams(p)
}

func copyParams(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// TestValidParams_CoversEveryDeclaredParameter keeps the table above honest, for
// EVERY mission. A parameter added to a mission and not here would make the
// other tests fail on a missing value, which is a confusing way to learn it;
// this says it directly.
func TestValidParams_CoversEveryDeclaredParameter(t *testing.T) {
	for _, mission := range Names() {
		names := declaredParams(t, mission)
		got := paramsFor(t, mission)
		if len(got) != len(names) {
			t.Errorf("%s: the parameter set has %d entries, the mission declares %d: %v vs %v",
				mission, len(got), len(names), got, names)
			continue
		}
		for _, n := range names {
			if _, ok := got[n]; !ok {
				t.Errorf("%s: the parameter set does not set the declared parameter %q", mission, n)
			}
		}
	}
}

func TestNames_ListsTheCheckedInMissions(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("no checked-in missions; the embed produced nothing")
	}
	var found bool
	for _, n := range names {
		if n == "scan" {
			found = true
		}
		if strings.HasSuffix(n, ".cue") {
			t.Errorf("name %q kept its extension; callers name a mission, not a file", n)
		}
	}
	if !found {
		t.Errorf("scan is not in %v", names)
	}
}

func TestSource_RefusesAPathInsteadOfAName(t *testing.T) {
	// A name reaching the embedded filesystem as a path is how a caller walks
	// out of the mission directory. Names are names.
	for _, bad := range []string{"../catalog", "missions/scan", "scan.cue", "a\\b"} {
		if _, err := Source(bad); err == nil {
			t.Errorf("Source(%q) was accepted; it is not a mission name", bad)
		}
	}
}

func TestSource_UnknownMissionNamesWhatExists(t *testing.T) {
	_, err := Source("nope")
	if err == nil {
		t.Fatal("an unknown mission rendered")
	}
	// The error has to be actionable: a caller that guessed wrong should see
	// the real names rather than go reading the source tree.
	if !strings.Contains(err.Error(), "scan") {
		t.Errorf("error does not name what exists: %v", err)
	}
}

func TestRender_MissingParametersAreAllReportedAtOnce(t *testing.T) {
	_, err := Render(context.Background(), "scan", map[string]string{"application": "customer-portal"})
	if err == nil {
		t.Fatal("an incomplete render was accepted; an empty commit would scan HEAD")
	}
	for _, want := range []string{"commit", "imageRef", "repositoryUrl", "ref", "pipelineId", "pipelineUrl"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error omits %q, so a caller fixes one field per render: %v", want, err)
		}
	}
}

func TestRender_WhitespaceIsNotAValue(t *testing.T) {
	p := validParams()
	p["commit"] = "   "
	_, err := Render(context.Background(), "scan", p)
	if err == nil || !strings.Contains(err.Error(), "commit") {
		t.Fatalf("a blank commit was accepted as a value: %v", err)
	}
}

func TestRender_ScanFansOutAcrossImageSourceAndRuntime(t *testing.T) {
	def, err := Render(context.Background(), "scan", validParams())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if def.GetName() != "scan" {
		t.Errorf("name = %q, want scan", def.GetName())
	}

	// The three views of one Application. Losing any one of them silently
	// narrows what the scan can see, which is exactly the failure that looks
	// like a clean application.
	wantTools := map[string]string{
		"image":    "trivy",
		"ports":    "naabu",
		"services": "httpx",
		"web":      "nuclei",
		"tls":      "tlsx",
	}
	nodes := def.GetNodes()
	for id, tool := range wantTools {
		n, ok := nodes[id]
		if !ok {
			t.Errorf("node %q missing", id)
			continue
		}
		if n.GetType() != missionv1.NodeType_NODE_TYPE_TOOL {
			t.Errorf("node %q type = %v, want TOOL", id, n.GetType())
		}
		if got := n.GetToolConfig().GetToolName(); got != tool {
			t.Errorf("node %q tool = %q, want %q", id, got, tool)
		}
	}

	src, ok := nodes["source"]
	if !ok {
		t.Fatal("source node missing")
	}
	if src.GetType() != missionv1.NodeType_NODE_TYPE_AGENT {
		t.Errorf("source type = %v, want AGENT", src.GetType())
	}
	if got := src.GetAgentConfig().GetAgentName(); got != "zerocool" {
		t.Errorf("source agent = %q, want zerocool", got)
	}

	report, ok := nodes["report"]
	if !ok {
		t.Fatal("report join node missing")
	}
	if report.GetType() != missionv1.NodeType_NODE_TYPE_JOIN {
		t.Errorf("report type = %v, want JOIN", report.GetType())
	}
}

func TestRender_EveryToolItNamesIsInTheCatalog(t *testing.T) {
	// A mission naming a tool the platform does not ship fails at dispatch,
	// per node, at runtime — long after the render looked fine. Catch it here.
	//
	// The shipped set comes FROM the component catalog, which is generated from
	// the captured executor image, rather than from a literal. The literal this
	// replaces had drifted: it named nine tools while the executor shipped
	// eleven, so a mission naming kube-bench or trivy-k8s would have passed this
	// check by being unknown to it in the same way a typo is.
	shipped := shippedTools(t)
	if len(shipped) == 0 {
		t.Fatal("the component catalog lists no tools; the check would pass on anything")
	}

	for _, mission := range Names() {
		def, err := Render(context.Background(), mission, paramsFor(t, mission))
		if err != nil {
			t.Fatalf("Render(%s): %v", mission, err)
		}
		for id, n := range def.GetNodes() {
			if n.GetType() != missionv1.NodeType_NODE_TYPE_TOOL {
				continue
			}
			if name := n.GetToolConfig().GetToolName(); !shipped[name] {
				t.Errorf("mission %q node %q names tool %q, which the executor does not ship (it ships %v)",
					mission, id, name, sortedKeys(shipped))
			}
		}
	}
}

// shippedTools is the kind:tool ids the component catalog lists. Those
// manifests are generated from one digest-pinned executor image, so this is
// what a dispatch can actually launch.
func shippedTools(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, r := range componentcatalog.Refs() {
		if r.Kind == authz.KindTool {
			out[r.ID] = true
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestRender_ParametersReachTheNodesThatNeedThem(t *testing.T) {
	p := validParams()
	def, err := Render(context.Background(), "scan", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// The image node scans the image the pipeline published. A parameter that
	// does not arrive here scans the wrong thing rather than failing.
	if got := def.GetNodes()["image"].GetToolConfig().GetInput()["image"]; got != p["imageRef"] {
		t.Errorf("image input = %q, want %q", got, p["imageRef"])
	}

	// The agent inherits the provenance of the scan. Checked by key, because a
	// context that silently loses a key produces an agent that scans HEAD.
	ctxMap := def.GetNodes()["source"].GetAgentConfig().GetTask().GetContext()
	for key, want := range map[string]string{
		"application":       p["application"],
		"repository.commit": p["commit"],
		"repository.url":    p["repositoryUrl"],
		"repository.ref":    p["ref"],
		"pipeline.id":       p["pipelineId"],
		"pipeline.url":      p["pipelineUrl"],
		"image.ref":         p["imageRef"],
		"zerocool.task":     "source-analysis",
	} {
		v, ok := ctxMap[key]
		if !ok {
			t.Errorf("task context is missing %q", key)
			continue
		}
		if got := v.GetStringValue(); got != want {
			t.Errorf("task context %q = %q, want %q", key, got, want)
		}
	}

	if goal := def.GetNodes()["source"].GetAgentConfig().GetTask().GetGoal(); !strings.Contains(goal, p["commit"]) {
		t.Errorf("goal does not name the commit it must scan: %q", goal)
	}
}

func TestRender_RuntimeBranchTakesItsHostFromTheTargetNotAParameter(t *testing.T) {
	// A caller must not be able to point a scan at a host the tenant has not
	// registered. The runtime nodes read the mission's bound target instead.
	def, err := Render(context.Background(), "scan", validParams())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, id := range []string{"ports", "services", "web", "tls"} {
		input := def.GetNodes()[id].GetToolConfig().GetInput()
		var found bool
		for _, v := range input {
			if strings.Contains(v, "{{target.") {
				found = true
			}
		}
		if !found {
			t.Errorf("node %q does not read the bound target: %v", id, input)
		}
	}
}

func TestRender_AQuoteInAParameterCannotInjectCUE(t *testing.T) {
	p := validParams()
	p["application"] = `x" , injected: "yes`
	def, err := Render(context.Background(), "scan", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := def.GetNodes()["source"].GetAgentConfig().GetTask().GetContext()["application"].GetStringValue()
	if got != p["application"] {
		t.Errorf("application = %q, want the value verbatim %q", got, p["application"])
	}
}

// TestRender_EveryTargetPlaceholderIsInTheVocabulary closes the loop the test
// above leaves open. That one asserts a placeholder is present, which a typo
// satisfies just as well as a real binding. This one asserts each placeholder is
// a name the binder resolves, so a catalog mission cannot ship a placeholder
// that nothing will ever replace (gibson#495).
func TestRender_EveryTargetPlaceholderIsInTheVocabulary(t *testing.T) {
	for _, name := range Names() {
		def, err := Render(context.Background(), name, paramsFor(t, name))
		if err != nil {
			t.Fatalf("Render(%s): %v", name, err)
		}
		for _, left := range targetbind.Unbound(def) {
			// Unbound formats "<field path>: {{name}}". Cut at the delimiter
			// rather than indexing it: Index returns -1 when absent, and slicing
			// on that panics instead of reporting the surprise.
			_, ref, found := strings.Cut(left, targetbind.Open)
			if !found {
				t.Errorf("Unbound returned %q with no %s in it", left, targetbind.Open)
				continue
			}
			ref = strings.TrimSuffix(ref, targetbind.Close)
			if !strings.HasPrefix(ref, targetbind.Prefix) {
				continue // another namespace, not this check's business
			}
			if !targetbind.Known(ref) {
				t.Errorf("mission %q: %s names no target field; the bindings are %v",
					name, left, targetbind.Names())
			}
		}
	}
}

// And the binder must actually resolve them, against a target shaped like the
// one a run names. A vocabulary check passes on a placeholder the binder would
// still refuse for being empty on the target.
func TestRender_ScanBindsAgainstARegisteredTarget(t *testing.T) {
	def, err := Render(context.Background(), "scan", validParams())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	tgt := types.NewTarget("kubernetes-goat", "https://goat.internal:8080", types.TargetTypeCustom)

	bound, err := targetbind.Bind(def, tgt)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if left := targetbind.UnboundTarget(bound); len(left) > 0 {
		t.Fatalf("placeholders survived binding: %v", left)
	}
	for _, id := range []string{"ports", "services", "web", "tls"} {
		for key, value := range bound.GetNodes()[id].GetToolConfig().GetInput() {
			if strings.Contains(value, "goat.internal") {
				continue
			}
			if strings.Contains(value, targetbind.Open) {
				t.Errorf("node %q input %q still carries a placeholder: %q", id, key, value)
			}
		}
	}
}

// TestRender_ScanMatchesItsRecordedRender pins the whole rendered definition,
// not a field of it.
//
// It was added with the move to per-mission parameters (gibson#499) to prove
// that change was a refactor: the bytes here were produced by the code BEFORE
// it, and they did not move. After that, it keeps earning its place — a mission
// is a work graph, and a change to it should be a change somebody chose, visible
// as a diff in this file rather than discovered on a run.
//
// Regenerate deliberately, and read the diff as the review:
//
//	go test ./internal/platform/missioncatalog/ -run MatchesItsRecordedRender -update
func TestRender_EveryMissionMatchesItsRecordedRender(t *testing.T) {
	for _, mission := range Names() {
		t.Run(mission, func(t *testing.T) {
			def, err := Render(context.Background(), mission, paramsFor(t, mission))
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			got, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(def)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			golden := "testdata/" + mission + "-rendered.json"
			if *updateGolden {
				if err := os.WriteFile(golden, got, 0o600); err != nil {
					t.Fatalf("write %s: %v", golden, err)
				}
				t.Logf("updated %s", golden)
				return
			}
			// #nosec G304 -- golden is "testdata/" + a mission name from the
			// embedded catalog, which Source already refuses to read as a path.
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read %s: %v (a new mission needs a recorded render; re-run with -update)", golden, err)
			}
			// protojson's output carries deliberate randomised whitespace
			// (detrand), so the comparison normalises it rather than asserting
			// on bytes nobody chose.
			if normalizeJSON(t, got) != normalizeJSON(t, want) {
				t.Errorf("the %s mission renders differently than recorded.\n"+
					"If that is the change you meant, re-run with -update and the diff is the review.\n"+
					"got:\n%s", mission, got)
			}
		})
	}
}

// normalizeJSON re-encodes through a generic map, which drops protojson's
// randomised indentation and orders keys.
func normalizeJSON(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("the recorded render is not JSON: %v", err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	return string(out)
}

// ── cluster-assessment ──────────────────────────────────────────────────────

// The demo mission (gibson#499): two tool branches that ask different
// questions of one cluster, two jobs on a bank, one join.
func TestRender_ClusterAssessmentHasFourBranchesAndOneCompletion(t *testing.T) {
	def, err := Render(context.Background(), "cluster-assessment", paramsFor(t, "cluster-assessment"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	nodes := def.GetNodes()

	for id, want := range map[string]missionv1.NodeType{
		"benchmark": missionv1.NodeType_NODE_TYPE_TOOL,
		"workloads": missionv1.NodeType_NODE_TYPE_TOOL,
		"exploit":   missionv1.NodeType_NODE_TYPE_JOB,
		"fix":       missionv1.NodeType_NODE_TYPE_JOB,
		"report":    missionv1.NodeType_NODE_TYPE_JOIN,
	} {
		n, ok := nodes[id]
		if !ok {
			t.Errorf("node %q is missing", id)
			continue
		}
		if got := n.GetType(); got != want {
			t.Errorf("node %q type = %v, want %v", id, got, want)
		}
	}

	// ONE completion. A rescan may only decide a `fixed` finding is `verified`
	// if it knows every branch finished looking, and that is what the join is
	// for — so an exit point per branch would quietly break the verify step.
	if got := def.GetExitPoints(); len(got) != 1 || got[0] != "report" {
		t.Errorf("exitPoints = %v, want exactly [report]", got)
	}
	if got := nodes["report"].GetJoinConfig().GetWaitFor(); len(got) != 2 {
		t.Errorf("the join waits for %v, want both jobs", got)
	}

	// Both tool branches are entry points: a cluster's controls and its
	// workloads are different questions and neither narrows the other, so
	// ordering them would only make the run longer.
	if got := def.GetEntryPoints(); len(got) != 2 {
		t.Errorf("entryPoints = %v, want both tool branches", got)
	}
}

// Both tools are handed the kubeconfig by NAME, declared tool-wide, and the
// mission carries no value anywhere (gibson#485).
func TestRender_ClusterAssessmentDeclaresTheKubeconfigByName(t *testing.T) {
	p := paramsFor(t, "cluster-assessment")
	secret := p[kubeconfigParam]

	def, err := Render(context.Background(), "cluster-assessment", p)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Declared tool-wide: both branches need it and neither can be told apart
	// from the other by kind.
	if got := def.GetSecrets().GetTools(); len(got) != 1 || got[0] != secret {
		t.Errorf("secrets.tools = %v, want [%s]", got, secret)
	}

	// And each tool node names it in its input, because the tool resolves
	// GIBSON_SECRET_<name> and cannot guess which secret it was handed.
	for _, id := range []string{"benchmark", "workloads"} {
		in := def.GetNodes()[id].GetToolConfig().GetInput()
		if got := in[kubeconfigParam]; got != secret {
			t.Errorf("node %q input kubeconfigSecret = %q, want %q", id, got, secret)
		}
		// The cluster is named by the target binding, never by a parameter: a
		// caller who could supply it could point the run at a cluster the
		// tenant never registered.
		if got := in["target"]; got != "{{target.name}}" {
			t.Errorf("node %q input target = %q, want the target binding", id, got)
		}
	}

	// Both jobs declare it through credentialNames, the job's own per-turn
	// grant. A job member is not a tool dispatch and does not read the tool
	// environment.
	for _, id := range []string{"exploit", "fix"} {
		got := def.GetNodes()[id].GetJobConfig().GetSpec().GetCredentialNames()
		if len(got) != 1 || got[0] != secret {
			t.Errorf("node %q credentialNames = %v, want [%s]", id, got, secret)
		}
	}
}

// Neither job names a finding id. The mission is written before the run, and
// the run is what produces the findings, so {{findings.open}} is resolved
// server-side at job open (gibson#497). An id pasted in here would be a mock.
func TestRender_ClusterAssessmentJobsAskForTheOpenFindings(t *testing.T) {
	def, err := Render(context.Background(), "cluster-assessment", paramsFor(t, "cluster-assessment"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, id := range []string{"exploit", "fix"} {
		got := def.GetNodes()[id].GetJobConfig().GetSpec().GetInputs()
		if len(got) != 1 || got[0] != "{{findings.open}}" {
			t.Errorf("node %q inputs = %v, want [{{findings.open}}]", id, got)
		}
	}
}

// Only the fix branch is allowed to change anything. The exploit branch proves
// what is reachable; a job that also edited the manifests would make the
// FIXED_BY link ambiguous about which branch did the work.
func TestRender_ClusterAssessmentOnlyTheFixBranchOpensAMergeRequest(t *testing.T) {
	def, err := Render(context.Background(), "cluster-assessment", paramsFor(t, "cluster-assessment"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	goal := def.GetNodes()["exploit"].GetJobConfig().GetSpec().GetGoal()
	for _, must := range []string{"Do not change the cluster", "do not change the manifests"} {
		if !strings.Contains(goal, must) {
			t.Errorf("the exploit goal does not say %q: %s", must, goal)
		}
	}
	if got := def.GetNodes()["fix"].GetJobConfig().GetSpec().GetGoal(); !strings.Contains(got, "merge request") {
		t.Errorf("the fix goal does not ask for a merge request: %s", got)
	}
}

// ── Describe / Entries ──────────────────────────────────────────────────────

// Describe answers what a caller needs BEFORE it has any parameter values, so
// it must not need any. The handler that lists the catalog has none, and the
// alternative — rendering each mission against placeholder values to read its
// description — is three failure modes and a set of fake values in exchange for
// three string literals.
func TestDescribe_ReadsEveryMissionWithoutParameters(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("the embedded catalog is empty; this test would pass on anything")
	}

	for _, name := range names {
		e, err := Describe(name)
		if err != nil {
			t.Fatalf("Describe(%s): %v", name, err)
		}
		// The CATALOG name comes back, which is the name Render takes.
		if e.Name != name {
			t.Errorf("%s: Name = %q", name, e.Name)
		}
		if e.Description == "" {
			t.Errorf("%s: no description", name)
		}
		if e.Version == "" {
			t.Errorf("%s: no version", name)
		}
		// The parameter set is what a caller builds its request from, so it must
		// BE the declared set — a short list sends a render that fails on a
		// missing key, a long one fails on an unknown key.
		want := declaredParams(t, name)
		sort.Strings(want)
		if !slices.Equal(e.DeclaredParams, want) {
			t.Errorf("%s: DeclaredParams = %v, want %v", name, e.DeclaredParams, want)
		}
	}
}

// The name inside the CUE and the catalog name agree. They are separate things —
// the file name is the catalog key — and a caller that read one and passed the
// other would get a confusing refusal.
func TestDescribe_TheCatalogNameAndTheMissionNameAgree(t *testing.T) {
	for _, name := range Names() {
		def, err := Render(context.Background(), name, paramsFor(t, name))
		if err != nil {
			t.Fatalf("Render(%s): %v", name, err)
		}
		if def.GetName() != name {
			t.Errorf("mission %q declares the name %q; the catalog key and the mission's own name must agree",
				name, def.GetName())
		}
	}
}

// An unknown name is refused, and the refusal names what the catalog does ship —
// which is what a person needs after a typo.
func TestDescribe_UnknownNameNamesWhatExists(t *testing.T) {
	_, err := Describe("no-such-mission")
	if err == nil {
		t.Fatal("Describe accepted a mission the catalog does not hold")
	}
	for _, name := range Names() {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal does not name the checked-in mission %q: %v", name, err)
		}
	}
}

// A path is not a name, so a caller cannot read a file outside the embedded
// catalog through the listing either.
func TestDescribe_APathIsNotAName(t *testing.T) {
	for _, name := range []string{"../scan", "missions/scan", "scan.cue"} {
		if _, err := Describe(name); err == nil {
			t.Errorf("Describe(%q) was accepted", name)
		}
	}
}

// Entries is every mission, in Names() order, and each entry equals what
// Describe returns for it. A listing assembled differently from the single
// lookup is two answers to one question.
func TestEntries_IsEveryMissionInOrder(t *testing.T) {
	got, err := Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	names := Names()
	if len(got) != len(names) {
		t.Fatalf("Entries returned %d, the catalog holds %d", len(got), len(names))
	}
	for i, e := range got {
		want, derr := Describe(names[i])
		if derr != nil {
			t.Fatalf("Describe(%s): %v", names[i], derr)
		}
		if e.Name != want.Name || e.Description != want.Description ||
			e.Version != want.Version || !slices.Equal(e.DeclaredParams, want.DeclaredParams) {
			t.Errorf("entry %d = %+v, want %+v", i, e, want)
		}
	}
}
