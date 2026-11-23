// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package componentcatalog

import (
	"reflect"
	"strings"
	"testing"
)

const hostedWithVariableNoPattern = `id: aap
kind: connector
spec:
  class: patch
  shape: Hosted
  image: registry.example.com/aap/mcp@sha256:abc
  transport: streamable-http
  auth: none
  port: 3000
  variables:
    - name: base_url
      env: BASE_URL
      kind: endpoint
`

// aapPatterns are the host patterns of the test connector.
const aapPatterns = "      patterns:\n" +
	"        - https://aap.corp-example.com:8443/*\n" +
	"        - https://aap.corp-example.com\n" +
	"        - https://aap.example.com\n"

const hostedWithVariable = hostedWithVariableNoPattern + aapPatterns

func aapEntry(t *testing.T, patterns string) ConnectorEntry {
	t.Helper()
	m, err := loadOne(t, hostedWithVariableNoPattern+patterns)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return m.toConnectorEntry()
}

func TestVariables_TheValueSetsTheEnvAndTheEgress(t *testing.T) {
	e := aapEntry(t, aapPatterns)
	got, err := e.ResolveVariables(map[string]string{"base_url": "https://aap.corp-example.com:8443/api"})
	if err != nil {
		t.Fatalf("ResolveVariables: %v", err)
	}
	if got.Env["BASE_URL"] != "https://aap.corp-example.com:8443/api" {
		t.Errorf("env = %v", got.Env)
	}
	if !reflect.DeepEqual(got.EgressAllow, []string{"aap.corp-example.com:8443"}) {
		t.Errorf("egress = %v: it must be the exact host and port, never a wildcard", got.EgressAllow)
	}
	// The default port is 443.
	got, err = e.ResolveVariables(map[string]string{"base_url": "https://aap.corp-example.com"})
	if err != nil || got.EgressAllow[0] != "aap.corp-example.com:443" {
		t.Errorf("default port: %v %v", got, err)
	}
}

// A tenant must not point the pod at an address that is not public.
func TestVariables_RefuseAnAddressThatIsNotPublic(t *testing.T) {
	e := aapEntry(t, aapPatterns)
	cases := map[string]string{
		"private v4":         "https://10.0.0.7/",
		"loopback":           "https://127.0.0.1/",
		"metadata":           "https://169.254.169.254/",
		"v6":                 "https://[::1]/",
		"localhost":          "https://localhost/",
		"cluster service":    "https://gibson-daemon.gibson.svc.cluster.local/",
		"short cluster name": "https://gibson-daemon.gibson.svc/",
		"local":              "https://aap.local/",
		"internal":           "https://aap.internal/",
		"corp":               "https://aap.corp/",
		"one label":          "https://aap/",
		"public suffix":      "https://com/",
		"arpa":               "https://7.0.0.10.in-addr.arpa/",
		"plain http":         "http://aap.example.com/",
		"user info":          "https://good.example.com@evil.example.net/",
		"query":              "https://aap.example.com/?x=1",
		"escape":             "https://aap.example.com/%2e%2e/",
		"wildcard":           "https://*.example.com/",
		"system port":        "https://aap.example.com:22/",
		"port 80":            "https://aap.example.com:80/",
		"upper case":         "https://AAP.example.com/",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := e.ResolveVariables(map[string]string{"base_url": raw}); err == nil {
				t.Fatalf("%q must be refused, got %+v", raw, got)
			}
		})
	}
}

func TestVariables_NeedEachDeclaredValueAndOnlyThose(t *testing.T) {
	e := aapEntry(t, aapPatterns)
	if _, err := e.ResolveVariables(nil); err == nil || !strings.Contains(err.Error(), "needs a value") {
		t.Errorf("a missing value must be refused: %v", err)
	}
	if _, err := e.ResolveVariables(map[string]string{"base_url": "https://aap.example.com/", "extra": "x"}); err == nil ||
		!strings.Contains(err.Error(), "declares no variable") {
		t.Errorf("an undeclared value must be refused: %v", err)
	}
}

func TestVariables_APatternLimitsTheHost(t *testing.T) {
	e := aapEntry(t, "      patterns:\n        - https://*.customer.example.com\n")
	if _, err := e.ResolveVariables(map[string]string{"base_url": "https://aap.customer.example.com/"}); err != nil {
		t.Fatalf("a value inside the pattern: %v", err)
	}
	for _, raw := range []string{
		"https://aap.other.example.com/",
		"https://a.b.customer.example.com/", // the wildcard is one label
		"https://customer.example.com.evil.example.net/",
	} {
		if _, err := e.ResolveVariables(map[string]string{"base_url": raw}); err == nil {
			t.Errorf("%q must be outside the pattern", raw)
		}
	}
}

func TestVariables_TheLoaderRefusesABadDeclaration(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"remote":          {responseConnector + "  variables:\n    - name: a\n      env: A\n      kind: endpoint\n", "need a Hosted connector"},
		"bad kind":        {strings.Replace(hostedWithVariable, "kind: endpoint", "kind: string", 1), "which must be"},
		"bad name":        {strings.Replace(hostedWithVariable, "name: base_url", "name: Base-Url", 1), "variable name"},
		"bad env":         {strings.Replace(hostedWithVariable, "env: BASE_URL", "env: 1BASE", 1), "not a valid variable name"},
		"env clash":       {hostedWithVariable + "  env:\n    BASE_URL: https://x\n", "already set"},
		"wildcard suffix": {hostedWithVariableNoPattern + "      patterns:\n        - https://*.herokuapp.com\n", "leaves the vendor domain"},
		"no pattern":      {hostedWithVariableNoPattern, "has no host pattern"},
		"twice":           {hostedWithVariable + "    - name: base_url\n      env: OTHER\n      kind: endpoint\n", "declared twice"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadOne(t, c.body)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error with %q, got %v", c.want, err)
			}
		})
	}
}

// Each connector of the catalog that takes a tenant URL refuses a public name
// that resolves to the metadata address, because no pattern allows it
// (review B3). The four connectors of a server that the customer hosts allow
// no value at all until the platform owner states a pattern.
func TestVariables_TheCatalogRefusesAHostThatNoPatternAllows(t *testing.T) {
	for _, m := range catalog {
		if m.connector == nil || len(m.connector.Variables) == 0 {
			continue
		}
		e := m.toConnectorEntry()
		values := map[string]string{}
		for _, v := range e.Variables {
			values[v.Name] = "https://169.254.169.254.nip.io/"
		}
		if got, err := e.ResolveVariables(values); err == nil {
			t.Errorf("%s accepted the metadata address: %+v", e.ID, got)
		}
	}
	for _, id := range []string{"prometheus-health", "puppet-patch"} {
		e, err := LookupConnector(id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.ResolveVariables(map[string]string{e.Variables[0].Name: "https://prom.customer-example.com/"}); err == nil ||
			!strings.Contains(err.Error(), "platform owner") {
			t.Errorf("%s with no install pattern: err = %v", id, err)
		}
	}
}

// The platform owner states the patterns of a server that the customer hosts.
// A key for a variable that takes no install pattern, an unknown connector and
// a bad pattern are refused, and then no pattern of the set applies.
func TestSetInstallPatterns(t *testing.T) {
	t.Cleanup(func() { _ = SetInstallPatterns(nil) })
	key := InstallPatternsKey("prometheus-health", "base_url")
	if err := SetInstallPatterns(map[string][]string{key: {"https://prom.customer-example.com"}}); err != nil {
		t.Fatal(err)
	}
	e, err := LookupConnector("prometheus-health")
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.ResolveVariables(map[string]string{"base_url": "https://prom.customer-example.com/"})
	if err != nil || got.EgressAllow[0] != "prom.customer-example.com:443" {
		t.Fatalf("resolve = %+v, %v", got, err)
	}
	if _, err := e.ResolveVariables(map[string]string{"base_url": "https://other.customer-example.com/"}); err == nil {
		t.Fatal("a host outside the install pattern was accepted")
	}
	for name, bad := range map[string]map[string][]string{
		"no slash":          {"prometheus-health": {"https://a.example.com"}},
		"unknown connector": {"no-such/base_url": {"https://a.example.com"}},
		"no install flag":   {InstallPatternsKey("okta-response", "org_url"): {"https://a.example.com"}},
		"bad pattern":       {key: {"https://*.herokuapp.com"}},
	} {
		if err := SetInstallPatterns(bad); err == nil {
			t.Errorf("%s: the set was accepted", name)
		}
	}
	if _, err := e.ResolveVariables(map[string]string{"base_url": "https://prom.customer-example.com/"}); err != nil {
		t.Fatalf("a refused set changed the patterns: %v", err)
	}
}

// The patterns hold the API hosts of the vendor clouds that the server READMEs
// and the vendor docs name (review M9).
func TestVariables_TheVendorCloudsAreAllowed(t *testing.T) {
	cases := map[string][]string{
		"crowdstrike-response": {
			"https://api.crowdstrike.com", "https://api.us-2.crowdstrike.com", "https://api.eu-1.crowdstrike.com",
			"https://api.laggar.gcw.crowdstrike.com", "https://api.us-gov-2.crowdstrike.mil",
		},
		"qualys-vmdr": {
			"https://qualysapi.qualys.com", "https://qualysapi.qg2.apps.qualys.com", "https://qualysapi.qg3.apps.qualys.com",
			"https://qualysapi.qg4.apps.qualys.com", "https://qualysapi.gov1.qualys.us", "https://qualysapi.qualys.eu",
			"https://qualysapi.qg2.apps.qualys.eu", "https://qualysapi.qg3.apps.qualys.it",
			"https://qualysapi.qg1.apps.qualys.in", "https://qualysapi.qg1.apps.qualys.ca",
			"https://qualysapi.qg1.apps.qualys.ae", "https://qualysapi.qg1.apps.qualys.co.uk",
			"https://qualysapi.qg1.apps.qualys.com.au", "https://qualysapi.qg1.apps.qualysksa.com",
		},
		"defender-endpoint-response": {
			"https://api.security.microsoft.com", "https://eu.api.security.microsoft.com",
			"https://api-gcc.security.microsoft.us", "https://api-gov.security.microsoft.us",
		},
	}
	for id, values := range cases {
		e, err := LookupConnector(id)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range values {
			if _, err := e.ResolveVariables(map[string]string{e.Variables[0].Name: v}); err != nil {
				t.Errorf("%s refuses %s: %v", id, v, err)
			}
		}
		if _, err := e.ResolveVariables(map[string]string{e.Variables[0].Name: "https://evil.example.com"}); err == nil {
			t.Errorf("%s accepts a host of no vendor", id)
		}
	}
}

// A default must match a pattern of the manifest, and it applies when the
// tenant gives no value (review M10).
func TestVariables_ADefault(t *testing.T) {
	e := aapEntry(t, aapPatterns+"      default: https://aap.example.com\n")
	got, err := e.ResolveVariables(nil)
	if err != nil || got.EgressAllow[0] != "aap.example.com:443" {
		t.Fatalf("resolve with the default = %+v, %v", got, err)
	}
	if _, err := loadOne(t, hostedWithVariable+"      default: https://other.example.net\n"); err == nil ||
		!strings.Contains(err.Error(), "default") {
		t.Fatalf("a default outside the patterns: err = %v", err)
	}
}

const caBundleVariable = "    - name: ca_bundle\n      kind: ca_bundle\n"

func aapWithCABundle(t *testing.T) ConnectorEntry {
	t.Helper()
	m, err := loadOne(t, hostedWithVariable+caBundleVariable)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return m.toConnectorEntry()
}

// The CA bundle is optional. It sets no env and adds no egress host
// (gibson#1517).
func TestVariables_CABundleIsOptionalAndSetsNoEnvOrEgress(t *testing.T) {
	e := aapWithCABundle(t)
	url := map[string]string{"base_url": "https://aap.example.com"}
	none, err := e.ResolveVariables(url)
	if err != nil {
		t.Fatalf("no bundle: %v", err)
	}
	if got, cerr := e.CABundleSecret(url); got != "" || cerr != nil {
		t.Errorf("CABundleSecret with no value = %q, %v", got, cerr)
	}
	withCA := map[string]string{"base_url": "https://aap.example.com", "ca_bundle": "aap-ca-corp"}
	got, err := e.ResolveVariables(withCA)
	if err != nil {
		t.Fatalf("with bundle: %v", err)
	}
	if !reflect.DeepEqual(got, none) {
		t.Errorf("the bundle changed the env or the egress: %+v vs %+v", got, none)
	}
	if name, cerr := e.CABundleSecret(withCA); name != "aap-ca-corp" || cerr != nil {
		t.Errorf("CABundleSecret = %q, %v", name, cerr)
	}
}

// The name must start with the prefix of the connector, so a tenant cannot
// send another secret, such as a vendor token, into the pod as a bundle.
func TestVariables_CABundleNameIsLimitedToThePrefix(t *testing.T) {
	e := aapWithCABundle(t)
	for name, v := range map[string]string{
		"another secret":     "aap-token",
		"prefix of another":  "github-fixloop-ca-x",
		"path escape":        "aap-ca-../token",
		"bad characters":     "aap-ca- x",
		"prefix only is not": "aap-ca",
	} {
		t.Run(name, func(t *testing.T) {
			vals := map[string]string{"base_url": "https://aap.example.com", "ca_bundle": v}
			if _, err := e.ResolveVariables(vals); err == nil {
				t.Errorf("ResolveVariables accepted %q", v)
			}
			if got, err := e.CABundleSecret(vals); err == nil {
				t.Errorf("CABundleSecret accepted %q as %q", v, got)
			}
		})
	}
}

func TestVariables_TheLoaderRefusesABadCABundleDeclaration(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"env":      {hostedWithVariable + caBundleVariable + "      env: SSL_CERT_FILE\n", "takes no env"},
		"default":  {hostedWithVariable + caBundleVariable + "      default: aap-ca-x\n", "takes no env"},
		"patterns": {hostedWithVariable + caBundleVariable + "      patterns:\n        - https://x.example.com\n", "takes no env"},
		"twice": {hostedWithVariable + caBundleVariable +
			"    - name: ca_two\n      kind: ca_bundle\n", "at most one variable of kind"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadOne(t, c.body); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error with %q, got %v", c.want, err)
			}
		})
	}
}
