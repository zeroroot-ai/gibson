// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/zitadelconn/zitadelconntest"
)

// wiringEnv is a complete Zitadel configuration for newZitadelWiring.
func wiringEnv(overrides map[string]string) func(string) string {
	env := map[string]string{
		"ZITADEL_URL":                           "http://gibson-zitadel:8080",
		"ZITADEL_EXTERNAL_DOMAIN":               "app.example.test",
		"ZITADEL_TENANT_OPERATOR_CLIENT_ID":     "tenant-operator",
		"ZITADEL_TENANT_OPERATOR_CLIENT_SECRET": "s3cret",
	}
	for k, v := range overrides {
		env[k] = v
	}
	return func(name string) string { return env[name] }
}

func TestNewZitadelWiring_BuildsEverythingFromOneEndpoint(t *testing.T) {
	w, err := newZitadelWiring(context.Background(), wiringEnv(nil))
	if err != nil {
		t.Fatalf("newZitadelWiring: %v", err)
	}
	if w.client == nil || w.tokens.API == nil || w.tokens.Platform == nil {
		t.Fatalf("wiring = %+v; want a client and both token sources", w)
	}
	if got := w.endpoint.BaseURL(); got != "http://gibson-zitadel:8080" {
		t.Errorf("endpoint base URL = %q, want ZITADEL_URL", got)
	}
	if got := w.endpoint.Host(); got != "app.example.test" {
		t.Errorf("endpoint host = %q, want ZITADEL_EXTERNAL_DOMAIN", got)
	}
}

// TestNewZitadelWiring_RefusesAnIncompleteConfiguration: each of the four env
// vars is required, a ported claimed host is refused (ADR-0092), and the
// operator must not start (one-code-path). ZITADEL_ISSUER is not among them:
// the operator no longer reads it.
func TestNewZitadelWiring_RefusesAnIncompleteConfiguration(t *testing.T) {
	for name, overrides := range map[string]map[string]string{
		"no ZITADEL_URL":             {"ZITADEL_URL": ""},
		"no ZITADEL_EXTERNAL_DOMAIN": {"ZITADEL_EXTERNAL_DOMAIN": ""},
		"a ported claimed host":      {"ZITADEL_EXTERNAL_DOMAIN": "app.example.test:443"},
		"no client ID":               {"ZITADEL_TENANT_OPERATOR_CLIENT_ID": ""},
		"no client secret":           {"ZITADEL_TENANT_OPERATOR_CLIENT_SECRET": ""},
	} {
		if _, err := newZitadelWiring(context.Background(), wiringEnv(overrides)); err == nil {
			t.Errorf("%s: newZitadelWiring = nil error, want refusal", name)
		}
	}
}

// TestNewZitadelWiring_PlatformTokenComesFromTheService is the gibson#222
// regression test. The token the operator sends to the dashboard comes from
// the in-cluster Zitadel Service, selected by the instance header. The fake
// answers 404 to a request that names no instance, and its claimed host can
// never resolve, so a client that dials the public issuer fails here.
func TestNewZitadelWiring_PlatformTokenComesFromTheService(t *testing.T) {
	fake := zitadelconntest.New(t, "", nil)
	w, err := newZitadelWiring(context.Background(), wiringEnv(map[string]string{
		"ZITADEL_URL":             fake.URL,
		"ZITADEL_EXTERNAL_DOMAIN": fake.Domain,
	}))
	if err != nil {
		t.Fatalf("newZitadelWiring: %v", err)
	}
	tok, err := w.tokens.Platform.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken != zitadelconntest.AccessToken {
		t.Errorf("access token = %q, want the token the Service issued", tok.AccessToken)
	}
	if n := fake.Refused(); n != 0 {
		t.Errorf("the fake refused %d request(s); the token request must carry the instance header", n)
	}
	if !fake.HasPath(http.MethodPost, "/oauth/v2/token") {
		t.Error("the token request did not reach the Service")
	}
}

func TestZitadelWiring_TenantRoleGrants(t *testing.T) {
	w, err := newZitadelWiring(context.Background(), wiringEnv(nil))
	if err != nil {
		t.Fatalf("newZitadelWiring: %v", err)
	}
	if g := w.tenantRoleGrants("PROJ-1"); g == nil {
		t.Fatal("tenantRoleGrants = nil; want grants")
	}
}

// TestZitadelWiringOrExit: a complete configuration yields the wiring and no
// exit. An incomplete one exits with status 1, which is what turns a
// misconfigured operator into a CrashLoopBackOff.
func TestZitadelWiringOrExit(t *testing.T) {
	exits := []int{}
	exit := func(code int) { exits = append(exits, code) }

	if w := zitadelWiringOrExit(context.Background(), wiringEnv(nil), exit); w == nil || len(exits) != 0 {
		t.Fatalf("complete configuration: wiring = %v, exits = %v; want the wiring and no exit", w, exits)
	}
	zitadelWiringOrExit(context.Background(), wiringEnv(map[string]string{"ZITADEL_URL": ""}), exit)
	if len(exits) != 1 || exits[0] != 1 {
		t.Fatalf("incomplete configuration: exits = %v; want one exit with status 1", exits)
	}
}
