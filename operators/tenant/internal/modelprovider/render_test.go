// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelprovider

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func testConfig() Config {
	return Config{
		Namespace: "gibson-gateway", GatewayName: "model-gateway",
	}
}

func provider(name, tenant string, spec gibsonv1alpha1.ModelProviderSpec) *gibsonv1alpha1.ModelProvider {
	spec.TenantID = tenant
	if spec.CredentialSecret == "" {
		spec.CredentialSecret = "provider-" + name
	}
	return &gibsonv1alpha1.ModelProvider{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "tenant-" + tenant},
		Spec:       spec,
	}
}

func renderYAML(t *testing.T, mp *gibsonv1alpha1.ModelProvider) []byte {
	t.Helper()
	objs, err := Render(mp, testConfig())
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
	cases := map[string]*gibsonv1alpha1.ModelProvider{
		"anthropic": provider("claude", "acme", gibsonv1alpha1.ModelProviderSpec{
			Type:        gibsonv1alpha1.ModelProviderAnthropic,
			ModelFilter: &gibsonv1alpha1.ModelFilter{Allow: []string{"claude-*", "haiku-4"}},
		}),
		"openai-compatible": provider("vllm", "acme", gibsonv1alpha1.ModelProviderSpec{
			Type:    gibsonv1alpha1.ModelProviderOpenAICompatible,
			BaseURL: "https://llm.example.com:8443/inference/v1",
		}),
		"private-ca": provider("mock", "acme", gibsonv1alpha1.ModelProviderSpec{
			Type:    gibsonv1alpha1.ModelProviderOpenAICompatible,
			BaseURL: "https://mockprovider.example.svc:8443/v1", CABundleSecret: "mock-ca",
		}),
		"bedrock": provider("aws", "acme", gibsonv1alpha1.ModelProviderSpec{
			Type: gibsonv1alpha1.ModelProviderBedrock, Region: "us-east-1",
		}),
		"vertexai": provider("gcp", "acme", gibsonv1alpha1.ModelProviderSpec{
			Type: gibsonv1alpha1.ModelProviderVertexAI, Region: "us-central1", ProjectID: "my-project",
		}),
		"gemini": provider("gem", "acme", gibsonv1alpha1.ModelProviderSpec{Type: gibsonv1alpha1.ModelProviderGemini}),
		"openai": provider("oai", "acme", gibsonv1alpha1.ModelProviderSpec{Type: gibsonv1alpha1.ModelProviderOpenAI}),
	}
	for name, mp := range cases {
		t.Run(name, func(t *testing.T) {
			got := renderYAML(t, mp)
			path := filepath.Join("testdata", name+".golden.yaml")
			if *update {
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v (run with -update)", path, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("render of %s differs from %s. Run with -update and read the diff.\n got:\n%s", name, path, got)
			}
		})
	}
}

func objectsOf(t *testing.T, mp *gibsonv1alpha1.ModelProvider) (backends, routes []*unstructured.Unstructured) {
	t.Helper()
	objs, err := Render(mp, testConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, o := range objs {
		switch o.GetKind() {
		case "AgentgatewayBackend":
			backends = append(backends, o)
		case "HTTPRoute":
			routes = append(routes, o)
		}
	}
	return backends, routes
}

// One backend and one route for a provider. Two backends for Bedrock.
func TestRender_ObjectCounts(t *testing.T) {
	for typ, want := range map[gibsonv1alpha1.ModelProviderType]int{
		gibsonv1alpha1.ModelProviderAnthropic: 1,
		gibsonv1alpha1.ModelProviderOpenAI:    1,
		gibsonv1alpha1.ModelProviderBedrock:   2,
		gibsonv1alpha1.ModelProviderGemini:    1,
	} {
		spec := gibsonv1alpha1.ModelProviderSpec{Type: typ, Region: "eu-west-1"}
		backends, routes := objectsOf(t, provider("p", "acme", spec))
		if len(backends) != want || len(routes) != 1 {
			t.Errorf("%s: %d backends and %d routes, want %d and 1", typ, len(backends), len(routes), want)
		}
	}
}

// A call of tenant A cannot match a route of tenant B. Each match of each route
// names the tenant, names the provider and holds one of the three model paths.
func TestRender_EachMatchNamesTheTenantAndThePath(t *testing.T) {
	allowed := map[string]bool{RouteResponses: true, RouteEmbeddings: true, RouteModels: true}
	for _, tenant := range []string{"acme", "globex"} {
		_, routes := objectsOf(t, provider("claude", tenant, gibsonv1alpha1.ModelProviderSpec{Type: gibsonv1alpha1.ModelProviderAnthropic}))
		rules, _, _ := unstructured.NestedSlice(routes[0].Object, "spec", "rules")
		seen := 0
		for _, r := range rules {
			matches, _ := r.(map[string]any)["matches"].([]any)
			for _, m := range matches {
				mm := m.(map[string]any)
				path, _, _ := unstructured.NestedString(mm, "path", "value")
				if !allowed[path] {
					t.Errorf("tenant %s: the route matches the path %q", tenant, path)
				}
				headers := map[string]string{}
				for _, h := range mm["headers"].([]any) {
					hm := h.(map[string]any)
					headers[hm["name"].(string)] = hm["value"].(string)
				}
				if headers[HeaderTenant] != tenant || headers[HeaderProvider] != "claude" {
					t.Errorf("tenant %s: headers = %v", tenant, headers)
				}
				seen++
			}
		}
		if seen != 3 {
			t.Errorf("tenant %s: %d matches, want 3", tenant, seen)
		}
	}
}

// The backend holds no ext-authz policy: it runs at the Gateway level, before any
// route. The backend names the credential Secret and no credential.
func TestRender_NoBackendExtAuthzAndCredentialReference(t *testing.T) {
	backends, _ := objectsOf(t, provider("claude", "acme", gibsonv1alpha1.ModelProviderSpec{Type: gibsonv1alpha1.ModelProviderAnthropic}))
	spec := backends[0].Object["spec"].(map[string]any)
	if _, found, _ := unstructured.NestedMap(spec, "policies", "extAuth"); found {
		t.Error("the backend holds an extAuth policy: it would run after the route policies")
	}
	name, _, _ := unstructured.NestedString(spec, "policies", "auth", "secretRef", "name")
	if name != CredentialSecretName("acme", "claude") {
		t.Errorf("credential secret = %q", name)
	}
	routes, _, _ := unstructured.NestedStringMap(spec, "policies", "ai", "routes")
	if routes[RouteResponses] != "Responses" || routes[RouteEmbeddings] != "Embeddings" || routes[RouteModels] != "Passthrough" {
		t.Errorf("format map = %v", routes)
	}
	if _, found := routes["/v1/messages"]; found {
		t.Error("/v1/messages is in the format map: one wire format only")
	}
}

// The Bedrock list backend is a plain host and has no AI policy. Both are signed.
func TestRender_BedrockBackends(t *testing.T) {
	backends, routes := objectsOf(t, provider("aws", "acme", gibsonv1alpha1.ModelProviderSpec{
		Type: gibsonv1alpha1.ModelProviderBedrock, Region: "us-east-1",
	}))
	runtime, control := backends[0].Object["spec"].(map[string]any), backends[1].Object["spec"].(map[string]any)
	if _, ok := runtime["ai"]; !ok {
		t.Error("the runtime backend is not an AI backend")
	}
	if host, _, _ := unstructured.NestedString(control, "static", "host"); host != "bedrock.us-east-1.amazonaws.com" {
		t.Errorf("control host = %q", host)
	}
	if _, has := control["policies"].(map[string]any)["ai"]; has {
		t.Error("the control backend has AI policies, which the CRD refuses on a non-AI backend")
	}
	if svc, _, _ := unstructured.NestedString(control, "policies", "auth", "aws", "serviceName"); svc != "bedrock" {
		t.Errorf("control signing name = %q, want bedrock", svc)
	}
	rules, _, _ := unstructured.NestedSlice(routes[0].Object, "spec", "rules")
	listRef := rules[1].(map[string]any)["backendRefs"].([]any)[0].(map[string]any)["name"]
	if !strings.HasSuffix(listRef.(string), "-control") {
		t.Errorf("the list rule goes to %v, want the control backend", listRef)
	}
}

func TestRender_Refusals(t *testing.T) {
	good := provider("claude", "acme", gibsonv1alpha1.ModelProviderSpec{Type: gibsonv1alpha1.ModelProviderAnthropic})
	if _, err := Render(good, Config{}); err == nil {
		t.Error("an empty config gave no error")
	}
	bad := map[string]*gibsonv1alpha1.ModelProvider{
		"tenant not a label": provider("claude", "Acme Corp", gibsonv1alpha1.ModelProviderSpec{Type: gibsonv1alpha1.ModelProviderAnthropic}),
		"name not a label":   provider("Claude_1", "acme", gibsonv1alpha1.ModelProviderSpec{Type: gibsonv1alpha1.ModelProviderAnthropic}),
		"unknown type":       provider("x", "acme", gibsonv1alpha1.ModelProviderSpec{Type: "nope"}),
		"base url not https": provider("x", "acme", gibsonv1alpha1.ModelProviderSpec{Type: gibsonv1alpha1.ModelProviderOpenAICompatible, BaseURL: "http://insecure.example.com"}),
	}
	for name, mp := range bad {
		if _, err := Render(mp, testConfig()); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestSplitBaseURL(t *testing.T) {
	tests := []struct {
		in, host, path string
		port           int
	}{
		{"https://api.example.com", "api.example.com", "", 443},
		{"https://api.example.com/", "api.example.com", "", 443},
		{"https://api.example.com:8443/v1/x/", "api.example.com", "/v1/x", 8443},
	}
	for _, tt := range tests {
		host, port, path, err := splitBaseURL(tt.in)
		if err != nil || host != tt.host || port != tt.port || path != tt.path {
			t.Errorf("splitBaseURL(%q) = %q %d %q %v", tt.in, host, port, path, err)
		}
	}
	if _, _, _, err := splitBaseURL("https://host:abc/x"); err == nil {
		t.Error("a bad port gave no error")
	}
}

func TestGlobToRegexp(t *testing.T) {
	if got := globToRegexp("claude-*-v1.2"); got != `^claude-.*-v1\.2$` {
		t.Errorf("globToRegexp = %q", got)
	}
}
