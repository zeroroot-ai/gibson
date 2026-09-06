// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package componentcatalog

import (
	"strings"
	"testing"
	"testing/fstest"
)

func manifestFSWith(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, body := range files {
		fsys["manifests/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

// TestLoad_AllKinds validates one valid manifest of every kind loads and
// discriminates into the right spec.
func TestLoad_AllKinds(t *testing.T) {
	fsys := manifestFSWith(map[string]string{
		"conn.yaml": "id: gl\nkind: connector\nspec:\n  shape: Remote\n  endpoint: https://x/mcp\n  auth: oauth\n",
		"plug.yaml": "id: pl\nkind: plugin\nspec:\n  runtime: pod\n  image: ghcr.io/x/p@sha256:abc\n",
		"tool.yaml": "id: nm\nkind: tool\nspec:\n  contentTrust: untrusted\n  dispatchMode: sandboxed\n  command: nmap\n  image: ghcr.io/x/t@sha256:abc\n",
		"agnt.yaml": "id: zc\nkind: agent\nspec:\n  runtime: pod\n  image: ghcr.io/x/a@sha256:abc\n  model: sonnet\n",
	})
	got, err := load(fsys)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 manifests, got %d", len(got))
	}
	byKind := map[string]Manifest{}
	for _, m := range got {
		byKind[m.Kind] = m
	}
	if byKind["connector"].connector == nil || byKind["plugin"].plugin == nil ||
		byKind["tool"].tool == nil || byKind["agent"].agent == nil {
		t.Fatalf("each kind must decode its own spec: %+v", byKind)
	}
	// Agent embeds the SAME WorkloadSpec as plugin (one code path) + policy.
	if a := byKind["agent"].agent; a.Runtime != "pod" || a.Image != "ghcr.io/x/a@sha256:abc" || a.Model != "sonnet" {
		t.Errorf("agent workload/policy = %+v", a)
	}
	if p := byKind["plugin"].plugin; p.Runtime != "pod" {
		t.Errorf("plugin workload = %+v", p)
	}
}

// TestLoad_FailLoud covers every per-kind rejection branch.
func TestLoad_FailLoud(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"missing id":             {"kind: agent\nspec:\n  runtime: pod\n  image: ghcr.io/x@sha256:a\n", "id is required"},
		"unknown kind":           {"id: x\nkind: gadget\nspec: {}\n", "must be one of"},
		"agent bare image":       {"id: x\nkind: agent\nspec:\n  runtime: pod\n  image: ghcr.io/x:latest\n", "digest-pinned"},
		"agent no image":         {"id: x\nkind: agent\nspec:\n  runtime: pod\n  model: sonnet\n", "digest-pinned"},
		"plugin bare image":      {"id: x\nkind: plugin\nspec:\n  runtime: pod\n  image: ghcr.io/x:latest\n", "digest-pinned"},
		"tool bare image":        {"id: x\nkind: tool\nspec:\n  dispatchMode: sandboxed\n  image: ghcr.io/x:latest\n", "digest-pinned"},
		"tool no image":          {"id: x\nkind: tool\nspec:\n  dispatchMode: sandboxed\n  command: nmap\n", "digest-pinned"},
		"sandboxed agent no cmd": {"id: x\nkind: agent\nspec:\n  runtime: setec\n  dispatchMode: sandboxed\n  image: ghcr.io/x@sha256:a\n", "must declare command"},
		"connector no endpoint":  {"id: x\nkind: connector\nspec:\n  shape: Remote\n  auth: none\n", "needs an endpoint"},
		"connector remote+image": {"id: x\nkind: connector\nspec:\n  shape: Remote\n  endpoint: https://x\n  image: y\n  auth: none\n", "must not set image"},
		"connector bad auth":     {"id: x\nkind: connector\nspec:\n  shape: Remote\n  endpoint: https://x\n  auth: bogus\n", "must be none, secret, or oauth"},
		"hosted first-party tag": {"id: x\nkind: connector\nspec:\n  shape: Hosted\n  image: ghcr.io/zeroroot-ai/foo:v1\n  auth: none\n", "digest-pinned"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := load(manifestFSWith(map[string]string{"m.yaml": tc.body}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestLoad_FirstPartyImagePolicy: a first-party image (ghcr.io/zeroroot-ai/…)
// must be digest-pinned so a tenant runs exactly the pipeline-signed build; a
// third-party vendor image on any other registry is the allowed vendor seam.
func TestLoad_FirstPartyImagePolicy(t *testing.T) {
	if _, err := load(manifestFSWith(map[string]string{
		"a.yaml": "id: fp\nkind: connector\nspec:\n  shape: Hosted\n  image: ghcr.io/zeroroot-ai/foo@sha256:abc\n  auth: none\n",
	})); err != nil {
		t.Fatalf("first-party digest-pinned image should load: %v", err)
	}
	if _, err := load(manifestFSWith(map[string]string{
		"b.yaml": "id: tp\nkind: connector\nspec:\n  shape: Hosted\n  image: ghcr.io/stackloklabs/osv-mcp/server\n  auth: none\n",
	})); err != nil {
		t.Fatalf("third-party vendor image should load (vendor seam): %v", err)
	}
}

func TestLoad_DuplicateAndEmpty(t *testing.T) {
	_, err := load(manifestFSWith(map[string]string{
		"a.yaml": "id: dup\nkind: agent\nspec:\n  runtime: pod\n  image: ghcr.io/x/a@sha256:aa\n",
		"b.yaml": "id: dup\nkind: agent\nspec:\n  runtime: pod\n  image: ghcr.io/x/b@sha256:bb\n",
	}))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate error, got %v", err)
	}
	if _, err := load(fstest.MapFS{}); err == nil {
		t.Fatal("empty catalog must error")
	}
}

// TestEmbeddedCatalog checks the shipped manifests load and every ref is
// well-formed. The catalog now ships both connectors and the zerocool agent.
func TestEmbeddedCatalog(t *testing.T) {
	refs := Refs()
	if len(refs) == 0 {
		t.Fatal("embedded catalog is empty")
	}
	for _, r := range refs {
		if r.Kind == "" || r.ID == "" {
			t.Errorf("empty ref: %+v", r)
		}
	}
	if len(ListConnectors()) == 0 {
		t.Error("embedded catalog should still ship connectors")
	}
}

func TestConnectorProjection(t *testing.T) {
	e, err := LookupConnector("gitlab")
	if err != nil {
		t.Fatalf("LookupConnector(gitlab): %v", err)
	}
	if e.DefaultInstanceURL == "" || e.Vendor == "" {
		t.Errorf("connector projection lost spec fields: %+v", e)
	}
	ci := e.BuildConnectorInstance("tenant-acme")
	if ci.Name != "gitlab" || ci.Namespace != "tenant-acme" || ci.Spec.Connector != "gitlab" {
		t.Errorf("BuildConnectorInstance wrong: %+v", ci.ObjectMeta)
	}
	if _, err := LookupConnector("nope"); err == nil {
		t.Error("LookupConnector(nope) should error")
	}
}

// TestAgentProjection loads a synthetic agent manifest and proves lookupAgent
// projects its image, runtime, model, budget and egress ceiling into an
// AgentEntry. No agent manifest ships yet (slice gibson#1598), so this exercises
// the projection against a loaded set rather than the embedded catalog.
func TestAgentProjection(t *testing.T) {
	entries, err := load(manifestFSWith(map[string]string{
		"zc.yaml": "id: zerocool\nkind: agent\n" +
			"displayName: ZeroCool\ndescription: flagship agent\n" +
			"egressAllow:\n  - api.anthropic.com:443\n" +
			"spec:\n  runtime: pod\n  image: ghcr.io/zeroroot-ai/zerocool@sha256:abc\n  model: sonnet\n  budgetLimit: 42\n",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	e, ok := lookupAgent(entries, "zerocool")
	if !ok {
		t.Fatal("lookupAgent(zerocool) not found")
	}
	if e.Image != "ghcr.io/zeroroot-ai/zerocool@sha256:abc" {
		t.Errorf("image = %q", e.Image)
	}
	if e.Runtime != "pod" || e.Model != "sonnet" || e.BudgetLimit != 42 {
		t.Errorf("workload/policy lost: %+v", e)
	}
	if e.DisplayName != "ZeroCool" || e.Description != "flagship agent" {
		t.Errorf("envelope lost: %+v", e)
	}
	if len(e.EgressAllow) != 1 || e.EgressAllow[0] != "api.anthropic.com:443" {
		t.Errorf("egress ceiling lost: %+v", e.EgressAllow)
	}
	if _, ok := lookupAgent(entries, "nope"); ok {
		t.Error("lookupAgent(nope) should not be found")
	}
	// A non-agent id must not project as an agent.
	if _, ok := lookupAgent(entries, "gitlab"); ok {
		t.Error("lookupAgent must ignore non-agent kinds")
	}
}

// TestLookupAgentEmbedded proves the exported accessor answers against the
// embedded catalog: an unlisted id returns ok=false so the resolver fails
// closed.
func TestLookupAgentEmbedded(t *testing.T) {
	if _, ok := LookupAgent("nope"); ok {
		t.Error("an unlisted agent must return ok=false")
	}
}

// TestZerocoolManifest proves the shipped zerocool agent manifest loads,
// projects its owner-locked policy, and seeds platform_enabled for its ref.
// Model and budget are resolved at dispatch, so the manifest pins neither
// (empty Model, zero BudgetLimit).
// TestClaudeManifestEgressIsUnconfined pins the posture the claude agent is
// dispatched under. "*" means gibson imposes no allow-list, so the sandbox
// takes its SandboxClass default (external-only: the public internet, never
// the operator's reserved ranges). A pinned destination list here cannot
// work for a coding agent, whose mission names hosts no manifest can know
// in advance, and re-pinning it silently breaks every such mission.
func TestClaudeManifestEgressIsUnconfined(t *testing.T) {
	e, ok := LookupAgent("claude")
	if !ok {
		t.Fatal("LookupAgent(claude): not listed in the embedded catalog")
	}
	if e.DispatchMode != DispatchModeSandboxed {
		t.Errorf("dispatchMode = %q, want %q", e.DispatchMode, DispatchModeSandboxed)
	}
	if len(e.EgressAllow) != 1 || e.EgressAllow[0] != "*" {
		t.Errorf("egressAllow = %+v, want [*] so the SandboxClass posture applies", e.EgressAllow)
	}
}

func TestZerocoolManifest(t *testing.T) {
	e, ok := LookupAgent("zerocool")
	if !ok {
		t.Fatal("LookupAgent(zerocool): not listed in the embedded catalog")
	}
	// The invariant is the repository and the digest pin, not one release's
	// digest. Asserting the literal made every image bump a two-file edit whose
	// second half is pure restatement — the guard failed for a correct change,
	// which is the defect class the workspace rules call out. What must never
	// drift is that this agent runs a digest-pinned image from the zeroroot
	// registry, and that is what this asserts.
	if !strings.HasPrefix(e.Image, "ghcr.io/zeroroot-ai/zerocool-agent@") {
		t.Errorf("image = %q, want the zerocool-agent image from the zeroroot registry", e.Image)
	}
	if !strings.Contains(e.Image, digestMarker) {
		t.Errorf("zerocool image must be digest-pinned (never a moving tag), got %q", e.Image)
	}
	if e.DispatchMode != DispatchModeSandboxed {
		t.Errorf("dispatchMode = %q, want %q", e.DispatchMode, DispatchModeSandboxed)
	}
	if len(e.EgressAllow) != 1 || e.EgressAllow[0] != "*" {
		t.Errorf("egressAllow = %+v, want [*]", e.EgressAllow)
	}
	if e.Model != "" {
		t.Errorf("model must not be pinned (resolved newest at dispatch), got %q", e.Model)
	}
	if e.BudgetLimit != 0 {
		t.Errorf("budgetLimit must be tenant default (0), got %d", e.BudgetLimit)
	}
	// It seeds platform_enabled: the ref set includes component:agent/zerocool.
	found := false
	for _, r := range Refs() {
		if r.Kind == "agent" && r.ID == "zerocool" {
			found = true
		}
	}
	if !found {
		t.Error("Refs() must include agent/zerocool so the seeder enables it")
	}
}

// TestAgentDispatchModeValidation rejects an agent dispatchMode that is neither
// empty nor "sandboxed", and accepts both allowed values.
func TestAgentDispatchModeValidation(t *testing.T) {
	if _, err := load(manifestFSWith(map[string]string{
		"bad.yaml": "id: x\nkind: agent\nspec:\n  runtime: setec\n  image: ghcr.io/x/a@sha256:aa\n  dispatchMode: bogus\n",
	})); err == nil || !strings.Contains(err.Error(), "dispatchMode") {
		t.Fatalf("want dispatchMode rejection, got %v", err)
	}
	for _, mode := range []string{"", "sandboxed"} {
		body := "id: x\nkind: agent\nspec:\n  runtime: setec\n  image: ghcr.io/x/a@sha256:aa\n"
		if mode != "" {
			// A sandboxed agent must also name its launch command.
			body += "  dispatchMode: " + mode + "\n  command: node /app/agent.js\n"
		}
		if _, err := load(manifestFSWith(map[string]string{"ok.yaml": body})); err != nil {
			t.Errorf("dispatchMode %q should load: %v", mode, err)
		}
	}
}

// TestLoad_AgentCredentials: a manifest may declare the tenant provider
// credentials its sandbox needs (gibson#1621). Malformed declarations fail loud.
func TestLoad_AgentCredentials(t *testing.T) {
	good := manifestFSWith(map[string]string{
		"claude.yaml": "id: claude\nkind: agent\nspec:\n  runtime: setec\n  image: ghcr.io/x/c@sha256:abc\n  credentials:\n    - provider: anthropic\n      env: ANTHROPIC_API_KEY\n",
	})
	got, err := load(good)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	e := got[0].toAgentEntry()
	if len(e.Credentials) != 1 || e.Credentials[0].Provider != "anthropic" || e.Credentials[0].Env != "ANTHROPIC_API_KEY" || e.Credentials[0].Key != "api_key" {
		t.Fatalf("credentials = %+v, want anthropic/ANTHROPIC_API_KEY with key defaulted to api_key", e.Credentials)
	}
	for name, spec := range map[string]string{
		"no provider":   "  credentials:\n    - env: ANTHROPIC_API_KEY\n",
		"bad env name":  "  credentials:\n    - provider: anthropic\n      env: anthropic-key\n",
		"launcher name": "  credentials:\n    - provider: anthropic\n      env: GIBSON_MODEL\n",
		"duplicate env": "  credentials:\n    - provider: anthropic\n      env: KEY\n    - provider: openai\n      env: KEY\n",
	} {
		bad := manifestFSWith(map[string]string{"c.yaml": "id: c\nkind: agent\nspec:\n  runtime: setec\n  image: ghcr.io/x/c@sha256:abc\n" + spec})
		if _, err := load(bad); err == nil {
			t.Errorf("%s: want load to fail loud", name)
		}
	}
}

// TestAgentEntry_CommandProjectsShellSplit: the manifest's command string
// reaches the launch spec as argv (setec needs at least one entry).
func TestAgentEntry_CommandProjectsShellSplit(t *testing.T) {
	c, err := load(manifestFSWith(map[string]string{"a.yaml": "id: a\nkind: agent\nspec:\n  runtime: setec\n  dispatchMode: sandboxed\n  image: ghcr.io/x@sha256:a\n  command: \"node /app/dist/sandbox.js\"\n"}))
	if err != nil {
		t.Fatal(err)
	}
	e, ok := lookupAgent(c, "a")
	if !ok {
		t.Fatal("agent a not listed")
	}
	if len(e.Command) != 2 || e.Command[0] != "node" || e.Command[1] != "/app/dist/sandbox.js" {
		t.Fatalf("Command = %v, want [node /app/dist/sandbox.js]", e.Command)
	}
}

// TestNmapManifest proves the first shared tool ships on the unified manifest
// path (ADR-0017): LookupTool resolves it with a digest-pinned image, and Refs()
// includes component:tool/nmap so the daemon seeds platform_enabled for it.
func TestNmapManifest(t *testing.T) {
	e, ok := LookupTool("nmap")
	if !ok {
		t.Fatal("LookupTool(nmap): not listed in the embedded catalog")
	}
	if !strings.Contains(e.Image, digestMarker) {
		t.Errorf("nmap image must be digest-pinned, got %q", e.Image)
	}
	if e.DispatchMode != "sandboxed" || e.ContentTrust != "untrusted" {
		t.Errorf("nmap must be sandboxed+untrusted, got dispatch=%q trust=%q", e.DispatchMode, e.ContentTrust)
	}
	if len(e.Command) == 0 {
		t.Error("nmap must declare a launch command")
	}
	seeded := false
	for _, r := range Refs() {
		if r.Kind == "tool" && r.ID == "nmap" {
			seeded = true
		}
	}
	if !seeded {
		t.Error("Refs() must include tool/nmap so the seeder enables it platform-wide")
	}
}

// TestImageRefs covers what the supply-chain verifier consumes: every catalog
// component that names an image, and nothing that does not (gibson#1639).
func TestImageRefs(t *testing.T) {
	refs := ImageRefs()
	if len(refs) == 0 {
		t.Fatal("the embedded catalog must name at least one image")
	}

	byID := map[string]ImageRef{}
	for _, r := range refs {
		if r.Image == "" {
			t.Errorf("%s/%s is listed with an empty image; components that name no image must be absent, "+
				"or a caller cannot tell \"declares none\" from \"declares an empty one\"", r.Kind, r.ID)
		}
		if r.Kind == "" || r.ID == "" {
			t.Errorf("image ref %+v is missing its kind or id", r)
		}
		byID[r.Kind+"/"+r.ID] = r
	}

	// nmap is a manifest tool, so it must appear with the executor image its
	// manifest pins — this is the link the verifier walks.
	tool, ok := LookupTool("nmap")
	if !ok {
		t.Fatal("nmap must exist in the embedded catalog")
	}
	got, ok := byID["tool/nmap"]
	if !ok {
		t.Fatal("a kind:tool manifest with an image must appear in ImageRefs")
	}
	if got.Image != tool.Image {
		t.Errorf("ImageRefs reports %q for nmap, its manifest pins %q", got.Image, tool.Image)
	}

	// Every FIRST-PARTY image must be digest-pinned: the loader enforces it and
	// the verifier depends on it, since a tag could be repointed after the
	// check. A third-party vendor image (a connector fronting someone else's
	// container) is a different trust seam — we never signed it, and it is not
	// held to this rule.
	const firstParty = "ghcr.io/zeroroot-ai/"
	sawThirdParty := false
	for _, r := range refs {
		if !strings.HasPrefix(r.Image, firstParty) {
			sawThirdParty = true
			continue
		}
		if !strings.Contains(r.Image, "@sha256:") {
			t.Errorf("%s/%s image %q is first-party and must be digest-pinned", r.Kind, r.ID, r.Image)
		}
	}
	if !sawThirdParty {
		t.Log("no third-party image in the catalog; the seam distinction is untested here")
	}
}

// TestLoad_AgentMinContextWindow: a manifest may declare the smallest context
// window its model must have (gibson#1692), and the loader refuses a
// declaration that nothing would enforce.
//
// The refusal matters more than the field. The floor is checked where the model
// is resolved, which is the sandboxed launch path; on any other dispatch mode
// nothing reads it. Accepting it there would ship a declaration that silently
// does nothing — the same shape of defect the floor itself exists to close.
func TestLoad_AgentMinContextWindow(t *testing.T) {
	const base = "id: t\nkind: agent\nspec:\n  runtime: setec\n  image: ghcr.io/x/t@sha256:abc\n"

	got, err := load(manifestFSWith(map[string]string{
		"t.yaml": base + "  dispatchMode: sandboxed\n  command: \"/t\"\n  minContextWindow: 32000\n",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	e, ok := lookupAgent(got, "t")
	if !ok {
		t.Fatal("agent t not listed")
	}
	if e.MinContextWindow != 32000 {
		t.Fatalf("MinContextWindow = %d, want 32000", e.MinContextWindow)
	}

	// An agent that declares no floor keeps the zero value, which the resolver
	// reads as "no floor" and dispatches exactly as it always has.
	got, err = load(manifestFSWith(map[string]string{
		"t.yaml": base + "  dispatchMode: sandboxed\n  command: \"/t\"\n",
	}))
	if err != nil {
		t.Fatalf("load without a floor: %v", err)
	}
	if e, _ := lookupAgent(got, "t"); e.MinContextWindow != 0 {
		t.Fatalf("MinContextWindow = %d for a manifest that declares none, want 0", e.MinContextWindow)
	}

	for name, spec := range map[string]string{
		// Nothing resolves a model on a non-sandboxed dispatch, so this floor
		// would never be checked.
		"floor without a sandboxed dispatch": "  minContextWindow: 32000\n",
		"negative floor":                     "  dispatchMode: sandboxed\n  command: \"/t\"\n  minContextWindow: -1\n",
	} {
		if _, err := load(manifestFSWith(map[string]string{"t.yaml": base + spec})); err == nil {
			t.Errorf("%s: want load to fail loud", name)
		}
	}
}

// TestCVETriageManifest_DeclaresItsContextFloor pins the floor on the shipped
// manifest, not just the loader's ability to carry one.
//
// It is a fixture for a silent failure: without it the agent still dispatches,
// still succeeds, and still returns explanations — just truncated ones, on
// whatever model the tenant happens to default to. Nothing downstream reports
// that, which is why the value is asserted here rather than trusted to review.
func TestCVETriageManifest_DeclaresItsContextFloor(t *testing.T) {
	e, ok := LookupAgent("cve-triage")
	if !ok {
		t.Fatal("cve-triage is not in the shipped catalog")
	}
	if e.MinContextWindow != 32000 {
		t.Fatalf("cve-triage minContextWindow = %d, want 32000 — one model call must hold every changed Finding", e.MinContextWindow)
	}
	if e.DispatchMode != DispatchModeSandboxed {
		t.Fatalf("cve-triage dispatchMode = %q, want %q — the floor is enforced only on that path", e.DispatchMode, DispatchModeSandboxed)
	}
}

// TestLoad_CredentialShapes: a manifest carries one credential block per login
// shape, and a malformed declaration fails loud (gibson#1714).
func TestLoad_CredentialShapes(t *testing.T) {
	const head = "id: claude\nkind: agent\nspec:\n  runtime: setec\n  image: ghcr.io/x/c@sha256:abc\n"

	t.Run("a shaped multi-variable block loads", func(t *testing.T) {
		got, err := load(manifestFSWith(map[string]string{
			"claude.yaml": head + "  credentials:\n" +
				"    - shape: bedrock\n      provider: bedrock\n      envs:\n" +
				"        - key: aws_access_key_id\n          env: AWS_ACCESS_KEY_ID\n" +
				"        - key: aws_session_token\n          env: AWS_SESSION_TOKEN\n          optional: true\n",
		}))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		e := got[0].toAgentEntry()
		if len(e.Credentials) != 1 {
			t.Fatalf("entry = %+v", e)
		}
		block := e.Credentials[0]
		if block.Shape != LoginShapeBedrock || len(block.Fields()) != 2 {
			t.Fatalf("credentials = %+v", block)
		}
		if !block.Fields()[1].Optional {
			t.Error("the session token must stay optional")
		}
	})

	t.Run("two shapes may name the same variable", func(t *testing.T) {
		if _, err := load(manifestFSWith(map[string]string{
			"claude.yaml": head + "  credentials:\n" +
				"    - shape: bedrock\n      provider: bedrock\n      envs:\n        - key: aws_region\n          env: REGION\n" +
				"    - shape: vertex\n      provider: vertex\n      envs:\n        - key: vertex_region\n          env: REGION\n",
		})); err != nil {
			t.Fatalf("two shapes naming one variable never collide at runtime: %v", err)
		}
	})

	for name, block := range map[string]string{
		"unknown shape":          "  credentials:\n    - shape: oauth\n      provider: anthropic\n      env: KEY\n",
		"subscription block":     "  credentials:\n    - shape: subscription\n      provider: anthropic\n      env: KEY\n",
		"neither env nor envs":   "  credentials:\n    - shape: api_key\n      provider: anthropic\n",
		"both env and envs":      "  credentials:\n    - provider: anthropic\n      env: KEY\n      envs:\n        - key: k\n          env: E\n",
		"envs entry with no key": "  credentials:\n    - provider: anthropic\n      envs:\n        - env: KEY\n",
		"duplicate env in one shape": "  credentials:\n    - shape: bedrock\n      provider: bedrock\n      envs:\n" +
			"        - key: a\n          env: KEY\n        - key: b\n          env: KEY\n",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, err := load(manifestFSWith(map[string]string{"claude.yaml": head + block})); err == nil {
				t.Fatalf("want a load error for %s", name)
			}
		})
	}
}

// TestLoad_MemberCommandAndJobCap: one image runs two shapes, so the member
// shape is a different command on the same manifest (ADR-0019, gibson#1717).
func TestLoad_MemberCommandAndJobCap(t *testing.T) {
	const head = "id: claude\nkind: agent\nspec:\n  runtime: setec\n  image: ghcr.io/x/c@sha256:abc\n" +
		"  dispatchMode: sandboxed\n  command: node /app/one.js\n"

	got, err := load(manifestFSWith(map[string]string{
		"claude.yaml": head + "  memberCommand: node /app/member.js\n  maxJobsInFlight: 2\n",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	e := got[0].toAgentEntry()
	if len(e.MemberCommand) != 2 || e.MemberCommand[1] != "/app/member.js" {
		t.Fatalf("memberCommand = %v, want the shell-split member entry point", e.MemberCommand)
	}
	if e.MaxJobsInFlight != 2 {
		t.Errorf("maxJobsInFlight = %d, want 2", e.MaxJobsInFlight)
	}

	// An agent with no member command simply cannot join a bank; that is not a
	// manifest error, it is what zerocool looks like.
	plain, err := load(manifestFSWith(map[string]string{"z.yaml": head}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(plain[0].toAgentEntry().MemberCommand) != 0 {
		t.Error("no memberCommand must project to none")
	}

	for name, spec := range map[string]string{
		"negative job cap": head + "  maxJobsInFlight: -1\n",
		"member command on a non-sandboxed dispatch": "id: c\nkind: agent\nspec:\n  runtime: setec\n" +
			"  image: ghcr.io/x/c@sha256:abc\n  memberCommand: node /app/member.js\n",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, err := load(manifestFSWith(map[string]string{"c.yaml": spec})); err == nil {
				t.Fatalf("want a load error for %s", name)
			}
		})
	}
}

// TestClaudeManifest_RunsBothShapes: the shipped manifest carries the member
// entry point and a cap, so a bank can launch it.
func TestClaudeManifest_RunsBothShapes(t *testing.T) {
	e, ok := LookupAgent("claude")
	if !ok {
		t.Fatal("the claude agent must be in the embedded catalog")
	}
	if len(e.MemberCommand) == 0 {
		t.Error("claude must declare a member command, or no bank can run it")
	}
	if e.MaxJobsInFlight < 1 {
		t.Errorf("maxJobsInFlight = %d, want at least one job per member", e.MaxJobsInFlight)
	}
	z, ok := LookupAgent("zerocool")
	if !ok {
		t.Fatal("the zerocool agent must be in the embedded catalog")
	}
	if len(z.MemberCommand) != 0 {
		t.Error("zerocool has no member driver, so it must declare no member command")
	}
}
