package providers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zero-day-ai/gibson/internal/llm"
)

// TestFactoryCoverage asserts every ProviderType in llm.SupportedProviderTypes()
// is routed to a real constructor by NewProvider — i.e., adding a new enum
// constant without updating the factory switch causes this test to fail.
//
// A provider constructor is allowed to fail for auth/credential reasons (we
// pass minimal configs); the only failure mode we reject is the catch-all
// "unknown provider type" error from the factory default branch.
func TestFactoryCoverage(t *testing.T) {
	for _, typ := range llm.SupportedProviderTypes() {
		t.Run(string(typ), func(t *testing.T) {
			cfg := minimalConfigFor(typ)
			_, err := NewProvider(cfg)
			// We allow errors — many providers will fail to construct without
			// real credentials or a running backend. What we disallow is the
			// factory default-case error which signals missing routing.
			if err != nil {
				msg := strings.ToLower(err.Error())
				assert.NotContains(t, msg, "unknown provider type",
					"provider %q hit the factory default branch — add a case to NewProvider", typ)
			}
		})
	}
}

// TestFactoryRejectsUnknownTypeWithSupportedList verifies the default branch
// still works for truly-unknown types and names every supported type so
// operators can diagnose typos.
func TestFactoryRejectsUnknownTypeWithSupportedList(t *testing.T) {
	_, err := NewProvider(llm.ProviderConfig{
		Type:         llm.ProviderType("definitely-not-a-provider"),
		APIKey:       "x",
		DefaultModel: "y",
	})
	if err == nil {
		t.Fatal("expected error for unknown provider type")
	}
	msg := err.Error()
	assert.Contains(t, strings.ToLower(msg), "unknown provider type")
	// Must name each supported type so operators can correct their config.
	for _, typ := range llm.SupportedProviderTypes() {
		if typ == llm.ProviderCustom {
			continue // custom is listed but doesn't appear in the error helper
		}
		assert.Contains(t, msg, string(typ), "error message missing %q", typ)
	}
}

// minimalConfigFor builds a ProviderConfig just complete enough for the
// factory to reach the constructor — actual construction may still fail
// on missing creds, but it shouldn't fall through to the default branch.
func minimalConfigFor(typ llm.ProviderType) llm.ProviderConfig {
	cfg := llm.ProviderConfig{
		Type:         typ,
		APIKey:       "stub-key",
		DefaultModel: "stub-model",
	}
	switch typ {
	case llm.ProviderBedrock:
		cfg.Extra = map[string]string{"aws_region": "us-east-1"}
	case llm.ProviderCloudflare:
		cfg.Extra = map[string]string{"cloudflare_account_id": "acct"}
	case llm.ProviderErnie:
		cfg.Extra = map[string]string{"ernie_access_key": "ak", "ernie_secret_key": "sk"}
	case llm.ProviderWatsonX:
		cfg.Extra = map[string]string{"watsonx_project_id": "proj"}
	case llm.ProviderLocal:
		cfg.Extra = map[string]string{"bin": "/bin/true"}
	}
	return cfg
}
