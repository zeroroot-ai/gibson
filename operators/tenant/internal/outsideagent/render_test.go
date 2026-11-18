// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package outsideagent

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func testConfig() Config { return Config{Namespace: "gibson-gateway", GatewayName: "agent-gateway"} }

func renderYAML(t *testing.T, a Agent) []byte {
	t.Helper()
	objs, err := Render(a, testConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var buf bytes.Buffer
	for i, o := range objs {
		if i > 0 {
			buf.WriteString("---\n")
		}
		b, err := yaml.Marshal(o.Object)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf.Write(b)
	}
	return buf.Bytes()
}

func TestRender_Golden(t *testing.T) {
	cases := map[string]Agent{
		"with-credential": {
			Tenant: "acme", Name: "partner-scout", URL: "https://agent.partner.example/a2a",
			CredentialSecret: "partner-key",
		},
		"no-credential": {Tenant: "acme", Name: "open-scout", URL: "https://open.partner.example:8443"},
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			got := renderYAML(t, a)
			path := filepath.Join("testdata", name+".golden.yaml")
			if *update {
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatalf("write golden: %v", err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("render differs from %s (run with -update to rewrite):\n%s", path, got)
			}
		})
	}
}

func find(objs []*unstructured.Unstructured, kind string) *unstructured.Unstructured {
	for _, o := range objs {
		if o.GetKind() == kind {
			return o
		}
	}
	return nil
}

// The route of an outside agent removes every x-gibson-* header and the task
// grant, on each rule. The route of the daemon keeps them, so an outside route
// that lost the removal would leak the tenant, the subject and the grant.
func TestRender_RouteRemovesEachInternalHeader(t *testing.T) {
	objs, err := Render(Agent{Tenant: "acme", Name: "scout", URL: "https://a.example/x"}, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	r := find(objs, "HTTPRoute")
	rules, _, _ := unstructured.NestedSlice(r.Object, "spec", "rules")
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2 (the endpoint and the card)", len(rules))
	}
	for i, raw := range rules {
		rule, _ := raw.(map[string]any)
		filters, _ := rule["filters"].([]any)
		var removed []any
		for _, f := range filters {
			fm, _ := f.(map[string]any)
			if fm["type"] == "RequestHeaderModifier" {
				removed, _ = fm["requestHeaderModifier"].(map[string]any)["remove"].([]any)
			}
		}
		got := map[string]bool{}
		for _, h := range removed {
			got[h.(string)] = true
		}
		for _, h := range RemovedHeaders() {
			if !got[h] {
				t.Errorf("rule %d does not remove %s", i, h)
			}
		}
		for _, must := range []string{
			"x-gibson-tenant", "x-gibson-subject", "x-gibson-mission", "x-gibson-task", "x-gibson-route-tenant",
			"x-gibson-route-agent", "x-gibson-route-bank", "x-gibson-identity-tenant", "x-gibson-identity-subject",
			"x-capability-grant",
		} {
			if !got[must] {
				t.Errorf("rule %d: the pinned list does not hold %s", i, must)
			}
		}
	}
}

// Each match holds the tenant and the agent, and only two exact paths match.
func TestRender_RouteMatchesTheTenantTheAgentAndTwoExactPaths(t *testing.T) {
	out := string(renderYAML(t, Agent{Tenant: "acme", Name: "scout", URL: "https://a.example"}))
	for _, want := range []string{
		"name: x-gibson-route-tenant\n", "value: acme\n", "name: x-gibson-route-agent\n", "value: scout\n",
		"value: /\n", "value: /agents/scout/.well-known/agent-card.json\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the route lacks %q", want)
		}
	}
	if strings.Contains(out, "PathPrefix") || strings.Contains(out, "RegularExpression") {
		t.Error("the route must match exact paths only")
	}
}

func TestRender_Refusals(t *testing.T) {
	good := Agent{Tenant: "acme", Name: "scout", URL: "https://a.example/x"}
	cases := map[string]func(a *Agent){
		"http URL":      func(a *Agent) { a.URL = "http://a.example/x" },
		"no host":       func(a *Agent) { a.URL = "https:///x" },
		"user info":     func(a *Agent) { a.URL = "https://u:p@a.example/x" },
		"query":         func(a *Agent) { a.URL = "https://a.example/x?y=1" },
		"fragment":      func(a *Agent) { a.URL = "https://a.example/x#y" },
		"bad port":      func(a *Agent) { a.URL = "https://a.example:99999/x" },
		"tenant":        func(a *Agent) { a.Tenant = "Acme_1" },
		"name":          func(a *Agent) { a.Name = "a/b" },
		"empty name":    func(a *Agent) { a.Name = "" },
		"a unix scheme": func(a *Agent) { a.URL = "unix:///var/run/x.sock" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := good
			mutate(&a)
			if _, err := Render(a, testConfig()); err == nil {
				t.Error("Render accepted the record, want an error")
			}
		})
	}
	if _, err := Render(good, Config{}); err == nil {
		t.Error("Render accepted an empty config")
	}
}

// The render holds no credential value. The backend names a Secret only.
func TestRender_HoldsNoCredentialValue(t *testing.T) {
	a := Agent{Tenant: "acme", Name: "scout", URL: "https://a.example", CredentialSecret: "partner-key"}
	objs, err := Render(a, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	b := find(objs, "AgentgatewayBackend")
	secret, _, _ := unstructured.NestedString(b.Object, "spec", "policies", "auth", "secretRef", "name")
	if secret != "oa-acme-scout-credential" {
		t.Errorf("secretRef = %q, want oa-acme-scout-credential", secret)
	}
	if _, found, _ := unstructured.NestedString(b.Object, "spec", "policies", "auth", "key"); found {
		t.Error("the backend holds an inline key")
	}
}
