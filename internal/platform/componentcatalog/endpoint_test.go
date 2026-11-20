// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"strings"
	"testing"
)

func remoteEntry(patterns ...string) ConnectorEntry {
	return ConnectorEntry{
		ID: "vendor", Shape: "Remote", EndpointPatterns: patterns,
	}
}

func TestResolveEndpoint_Accepts(t *testing.T) {
	cases := map[string]struct {
		patterns []string
		endpoint string
		want     string
		egress   string
	}{
		"wildcard host": {[]string{"https://*.service-now.com/sncapps/mcp-server/mcp/*"},
			"https://acme.service-now.com/sncapps/mcp-server/mcp/secops",
			"https://acme.service-now.com/sncapps/mcp-server/mcp/secops", "acme.service-now.com:443"},
		"exact host": {[]string{"https://mcp.eu.example.com/mcp"},
			"https://mcp.eu.example.com/mcp", "https://mcp.eu.example.com/mcp", "mcp.eu.example.com:443"},
		"port in pattern": {[]string{"https://*.example.com:8089/services/mcp"},
			"https://a.example.com:8089/services/mcp", "https://a.example.com:8089/services/mcp", "a.example.com:8089"},
		"explicit default port": {[]string{"https://*.example.com/mcp"},
			"https://a.example.com:443/mcp", "https://a.example.com/mcp", "a.example.com:443"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := remoteEntry(tc.patterns...).ResolveEndpoint(tc.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if got.Endpoint != tc.want || len(got.EgressAllow) != 1 || got.EgressAllow[0] != tc.egress {
				t.Fatalf("got %+v, want %s and egress [%s]", got, tc.want, tc.egress)
			}
		})
	}
}

// A tenant must not point the proxy at a host that it picks freely, at an
// address of the cluster, or at a private address.
func TestResolveEndpoint_Refuses(t *testing.T) {
	e := remoteEntry("https://*.service-now.com/mcp/*")
	for name, ep := range map[string]string{
		"other domain":         "https://acme.evil.com/mcp/x",
		"suffix trick":         "https://acme.service-now.com.evil.com/mcp/x",
		"prefix trick":         "https://evilservice-now.com/mcp/x",
		"two labels for the *": "https://a.b.service-now.com/mcp/x",
		"apex":                 "https://service-now.com/mcp/x",
		"user info":            "https://service-now.com@evil.com/mcp/x",
		"user info on vendor":  "https://u:p@acme.service-now.com/mcp/x",
		"http":                 "http://acme.service-now.com/mcp/x",
		"ip literal":           "https://10.0.0.5/mcp/x",
		"ipv6 literal":         "https://[::1]/mcp/x",
		"cluster service":      "https://gibson-daemon.gibson.svc.cluster.local/mcp/x",
		"localhost":            "https://localhost/mcp/x",
		"metadata ip":          "https://169.254.169.254/mcp/x",
		"other port":           "https://acme.service-now.com:8443/mcp/x",
		"wrong path":           "https://acme.service-now.com/other/x",
		"path too long":        "https://acme.service-now.com/mcp/x/y",
		"dot dot":              "https://acme.service-now.com/mcp/..",
		"escape":               "https://acme.service-now.com/mcp/%2e%2e",
		"query":                "https://acme.service-now.com/mcp/x?a=b",
		"fragment":             "https://acme.service-now.com/mcp/x#f",
		"upper case host":      "https://ACME.service-now.com/mcp/x",
		"trailing dot":         "https://acme.service-now.com./mcp/x",
		"backslash":            "https://acme.service-now.com\\@evil.com/mcp/x",
		"empty":                "",
		"space":                "https://acme.service-now.com/mcp/x y",
	} {
		t.Run(name, func(t *testing.T) {
			if ep == "" {
				return // an empty endpoint selects the default, tested below
			}
			if got, err := e.ResolveEndpoint(ep); err == nil {
				t.Fatalf("accepted %q as %+v", ep, got)
			}
		})
	}
}

func TestResolveEndpoint_DefaultsAndKinds(t *testing.T) {
	fixed := ConnectorEntry{ID: "f", Shape: "Remote", Endpoint: "https://mcp.x.com/mcp", EgressAllow: []string{"mcp.x.com:443"}}
	got, err := fixed.ResolveEndpoint("")
	if err != nil || got.Endpoint != fixed.Endpoint || got.EgressAllow[0] != "mcp.x.com:443" {
		t.Fatalf("default: %+v %v", got, err)
	}
	if _, err := fixed.ResolveEndpoint("https://mcp.x.com/mcp"); err == nil || !strings.Contains(err.Error(), "takes no tenant endpoint") {
		t.Fatalf("a fixed connector accepted a tenant endpoint: %v", err)
	}
	if _, err := remoteEntry("https://*.x.com/mcp").ResolveEndpoint(""); err == nil {
		t.Fatal("a connector with no default endpoint accepted no endpoint")
	}
	hosted := ConnectorEntry{ID: "h", Shape: "Hosted", EgressAllow: []string{"a.com:443"}}
	if _, err := hosted.ResolveEndpoint("https://a.com/mcp"); err == nil {
		t.Fatal("a Hosted connector accepted an endpoint")
	}
}

func TestLoad_EndpointPatternPolicy(t *testing.T) {
	head := "id: x\nkind: connector\nspec:\n  class: siem\n  shape: Remote\n  auth: secret\n"
	cases := map[string]struct{ body, want string }{
		"wildcard host only":          {head + "  endpointPatterns: ['https://*/mcp']\n", "must have at least two labels"},
		"wildcard on a TLD":           {head + "  endpointPatterns: ['https://*.com/mcp']\n", "public suffix"},
		"wildcard on a public suffix": {head + "  endpointPatterns: ['https://*.herokuapp.com/mcp']\n", "public suffix"},
		"wildcard on co.uk":           {head + "  endpointPatterns: ['https://*.co.uk/mcp']\n", "public suffix"},
		"wildcard in the middle":      {head + "  endpointPatterns: ['https://a.*.example.com/mcp']\n", "first label"},
		"two wildcards":               {head + "  endpointPatterns: ['https://*.*.example.com/mcp']\n", "first label"},
		"partial wildcard":            {head + "  endpointPatterns: ['https://a*.example.com/mcp']\n", "not a valid DNS label"},
		"http pattern":                {head + "  endpointPatterns: ['http://*.example.com/mcp']\n", "scheme must be https"},
		"ip pattern":                  {head + "  endpointPatterns: ['https://10.0.0.1/mcp']\n", "IP address"},
		"query in pattern":            {head + "  endpointPatterns: ['https://*.example.com/mcp?a=b']\n", "no escape, query"},
		"default outside patterns":    {head + "  endpoint: https://mcp.other.com/mcp\n  endpointPatterns: ['https://*.example.com/mcp']\n", "matches none of endpointPatterns"},
		"egress with no default":      {head + "  endpointPatterns: ['https://*.example.com/mcp']\negressAllow: [a.example.com:443]\n", "must state no egressAllow"},
		"hosted with patterns":        {"id: x\nkind: connector\nspec:\n  class: siem\n  shape: Hosted\n  image: a@sha256:b\n  auth: none\n  endpointPatterns: ['https://*.example.com/mcp']\n", "must not set endpoint or endpointPatterns"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			body := tc.body
			if strings.Contains(body, "\negressAllow") {
				// egressAllow belongs to the envelope, not to spec.
				body = "egressAllow: [a.example.com:443]\n" + strings.Replace(body, "\negressAllow: [a.example.com:443]\n", "\n", 1)
			}
			_, err := load(manifestFSWith(map[string]string{"m.yaml": body}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
	ok := head + "  endpointPatterns: ['https://*.example.com/mcp']\n"
	if _, err := load(manifestFSWith(map[string]string{"m.yaml": ok})); err != nil {
		t.Fatalf("a valid pattern manifest failed: %v", err)
	}
}
