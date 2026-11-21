// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
)

// The install patterns come from the environment. A value that does not parse
// and a pattern that the catalog refuses fail the start (review B3).
func TestLoadConnectorInstallPatterns(t *testing.T) {
	t.Cleanup(func() { _ = componentcatalog.SetInstallPatterns(nil) })
	env := func(v string) func(string) string { return func(string) string { return v } }
	if err := loadConnectorInstallPatterns(env(`{"prometheus-health/base_url":["https://prom.customer-example.com"]}`)); err != nil {
		t.Fatal(err)
	}
	e, err := componentcatalog.LookupConnector("prometheus-health")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ResolveVariables(map[string]string{"base_url": "https://prom.customer-example.com/"}); err != nil {
		t.Fatalf("a host inside the install pattern: %v", err)
	}
	for _, bad := range []string{`{`, `{"okta-response/org_url":["https://a.example.com"]}`} {
		if err := loadConnectorInstallPatterns(env(bad)); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if err := loadConnectorInstallPatterns(env("")); err != nil {
		t.Fatal(err)
	}
}
