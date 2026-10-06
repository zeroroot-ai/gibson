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
