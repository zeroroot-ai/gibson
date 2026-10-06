// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// testTD is the trust domain of the policy tests. It is not zeroroot.ai on
// purpose: the daemon builds each platform SPIFFE ID from the configured
// trust domain, and no code holds a domain as a literal (ADR-0164).
var testTD = spiffeid.RequireTrustDomainFromString("example.org")

func TestPlatformSVIDsFollowTheTrustDomain(t *testing.T) {
	if got := tenantOperatorSVID(testTD); got != "spiffe://example.org/platform/tenant-operator" {
		t.Errorf("tenant operator = %q", got)
	}
	if got := connectorOperatorSVID(testTD); got != "spiffe://example.org/platform/connector-operator" {
		t.Errorf("connector operator = %q", got)
	}
	policies := spiffePeerMethodPolicies(testTD, api.ConnectionPointCallers{})
	for svid := range policies {
		id, err := spiffeid.FromString(svid)
		if err != nil || id.TrustDomain() != testTD {
			t.Errorf("policy key %q is not in %s", svid, testTD.Name())
		}
	}
	if _, ok := policies[tenantOperatorSVID(testTD)]; !ok {
		t.Error("the tenant operator of the configured trust domain has no policy")
	}
}

func TestRequireSPIFFETrustDomain(t *testing.T) {
	envoy := spiffeid.RequireFromString("spiffe://example.org/ns/gibson/sa/envoy")
	if err := requireSPIFFETrustDomain("example.org", envoy); err != nil {
		t.Fatalf("a valid trust domain was refused: %v", err)
	}
	for name, td := range map[string]string{"empty": "", "invalid": "Not A Domain", "other domain": "other.example"} {
		if err := requireSPIFFETrustDomain(td, envoy); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDaemonSPIFFETrustDomainComesFromConfig(t *testing.T) {
	withTD := func(td string) *daemonImpl {
		return &daemonImpl{config: &config.Config{Auth: config.AuthConfig{SPIFFE: &config.SPIFFEConfig{TrustDomain: td}}}}
	}
	if got := withTD("example.org").spiffeTrustDomain(); got != testTD {
		t.Errorf("configured trust domain = %q, want %q", got.Name(), testTD.Name())
	}
	for name, d := range map[string]*daemonImpl{
		"no config":    {},
		"no spiffe":    {config: &config.Config{}},
		"invalid name": withTD("Not A Domain"),
	} {
		if got := d.spiffeTrustDomain(); !got.IsZero() {
			t.Errorf("%s: trust domain = %q, want the zero value", name, got.Name())
		}
	}
}

// The daemon reads the Envoy SVID from the config, else from the env, and
// refuses to start without a valid Envoy SVID in the configured trust domain.
func TestSPIFFEStartIdentity(t *testing.T) {
	const envoy = "spiffe://example.org/ns/gibson/sa/envoy"
	noEnv := func(string) string { return "" }
	envoyEnv := func(k string) string {
		if k == "GIBSON_SPIFFE_ENVOY_ID" {
			return envoy
		}
		return ""
	}

	id, td, err := spiffeStartIdentity(&config.SPIFFEConfig{EnvoyID: envoy, TrustDomain: " example.org "}, noEnv)
	if err != nil || id != envoy || td != "example.org" {
		t.Fatalf("config: id=%q td=%q err=%v", id, td, err)
	}
	if id, _, err = spiffeStartIdentity(&config.SPIFFEConfig{TrustDomain: "example.org"}, envoyEnv); err != nil || id != envoy {
		t.Fatalf("env: id=%q err=%v", id, err)
	}
	for name, c := range map[string]struct {
		cfg    *config.SPIFFEConfig
		getenv func(string) string
	}{
		"no envoy id":        {&config.SPIFFEConfig{TrustDomain: "example.org"}, noEnv},
		"invalid envoy id":   {&config.SPIFFEConfig{EnvoyID: "not a spiffe id", TrustDomain: "example.org"}, noEnv},
		"no trust domain":    {&config.SPIFFEConfig{EnvoyID: envoy}, noEnv},
		"other trust domain": {&config.SPIFFEConfig{EnvoyID: envoy, TrustDomain: "other.example"}, noEnv},
	} {
		if _, _, err := spiffeStartIdentity(c.cfg, c.getenv); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
